from generate_code import generate_code, generate_path
from process_elf import process_elf
import http.server
import socketserver
import subprocess
import os
import random
import string
import time
import urllib.parse

class MyHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open("index.html", "rb") as f:
                self.wfile.write(f.read())
        elif self.path == '/generate':
            # Generate unique filename and source code
            client_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
            exefile_name = f"build/chall-{client_id}"
            srcfile_name = f"build/chall-{client_id}.c"
            path = generate_path()
            print(f"Generated path: {''.join(path)}")
            code = generate_code(path)
            with open(srcfile_name, 'w') as f:
                f.write(code)

            # Compile the code
            compile_command = ["gcc", "-o", exefile_name, srcfile_name, "-falign-functions=1024", "-lcrypto"]
            subprocess.run(compile_command)
            process_elf(exefile_name)
            strip_command = ["strip", exefile_name]
            subprocess.run(strip_command)

            # Track the challenge info
            challenge_id = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
            download_links[challenge_id] = {
                'file': exefile_name,
                'path': ''.join(path)
            }


            # Return the file for download
            if os.path.exists(exefile_name):
                self.send_response(200)
                self.send_header("Content-type", "application/octet-stream")
                self.send_header("Content-Disposition", f"attachment; filename={os.path.basename(exefile_name)}")
                self.send_header("Challenge-ID", challenge_id)
                self.end_headers()
                with open(exefile_name, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404, "File not found")

        elif self.path.startswith('/reset'):
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Time limit exceeded.\n")

            challenge_id = self.path.split('/')[-1]
            if challenge_id in download_links:
                file_info = download_links[challenge_id]
                # Clean up files
                os.remove(file_info['file'])
                os.remove(file_info['file'] + '.c')
                del download_links[challenge_id]
                

        else:
            self.send_error(404, "File not found")

    def do_POST(self):
        if self.path.startswith('/submit/'):
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode()
            post_data = urllib.parse.parse_qs(post_data)
            flag = post_data['flag'][0]
            challenge_id = self.path.split('/')[-1]

            if challenge_id in download_links:
                file_info = download_links[challenge_id]
                correct_path = file_info['path']

                if flag == correct_path:
                    self.send_response(200)
                    self.send_header("Content-type", "text/plain")
                    self.end_headers()
                    self.wfile.write(f"Congratulations! Here is your flag: {FLAG}\n".encode())
                else:
                    self.send_response(200)
                    self.send_header("Content-type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"Incorrect flag, try again.\n")

                # Clean up files
                os.remove(file_info['file'])
                os.remove(file_info['file'] + '.c')
                del download_links[challenge_id]
            else:
                self.send_error(404, "Challenge not found")

if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 8001
    download_links = {}
    FLAG = "flag{smc_and_autorev_are_awesome}"

    # Create and start the HTTP server
    with socketserver.TCPServer((HOST, PORT), MyHTTPHandler) as httpd:
        print(f"HTTP server started, listening on {HOST}:{PORT}")
        httpd.serve_forever()
