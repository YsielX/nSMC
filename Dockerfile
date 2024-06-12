FROM python:3.10

WORKDIR /root/autore

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y gcc
EXPOSE 12345

COPY . .

CMD ["python", "server.py"]