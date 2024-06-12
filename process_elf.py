from Crypto.Cipher import AES, DES, ARC4, Blowfish, ChaCha20
import lief


def make_text_writable(elf):
    text_section = next(s for s in elf.sections if s.name == '.text')
    text_section.add(lief.ELF.SECTION_FLAGS.WRITE)
    for segment in elf.segments:
        if text_section in segment.sections:
            segment.flags |= lief.ELF.SEGMENT_FLAGS.W
        

def encrypt_aes(data, key, iv):
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(data)

def encrypt_des(data, key, iv):
    des = DES.new(key, DES.MODE_CBC, iv)
    return des.encrypt(data)

def encrypt_blowfish(data, key, iv):
    blowfish = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    return blowfish.encrypt(data)

def encrypt_arc4(data, key, iv):
    arc4 = ARC4.new(key)
    return arc4.encrypt(data)

def encrypt_xor(data, key, iv):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

encrypt_table = {
    'aes128': encrypt_aes,
    'aes192': encrypt_aes,
    'aes256': encrypt_aes,
    'des': encrypt_des,
    'blowfish': encrypt_blowfish,
    'rc4': encrypt_arc4,
    'xor': encrypt_xor,
    '': lambda data, key, iv: data
}

def encrypt_functions(elf):
    functions = [sym for sym in elf.symbols if sym.type == lief.ELF.SYMBOL_TYPES.FUNC]
    for func in functions:
        addr = func.value
        name = func.name
        if name.startswith('check'):
            _, encrypt, key, iv = name.split('_')
            data = elf.get_content_from_virtual_address(addr, 0x400)

            encrypt_func = encrypt_table[encrypt]
            key = bytes.fromhex(key)
            iv = bytes.fromhex(iv) if iv != 'None' and iv else None
            encrypted_data = encrypt_func(data, key, iv)
            encrypted_data = [i for i in encrypted_data]

            elf.patch_address(addr, encrypted_data)


def process_elf(path):
    elf = lief.parse(path)
    make_text_writable(elf)
    encrypt_functions(elf)
    elf.write(path)

if __name__ == '__main__':
    process_elf('chall')