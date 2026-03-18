import os
import socket
from Crypto.Cipher import AES

key = b"TheProjectSubmit"
nonce = b"tHEpROJECTsUBMIT"
cipher = AES.new(key, AES.MODE_EAX, nonce)
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP socket
client.connect(("localhost", 9999))  # connect to localhost:9999
file_size = os.path.getsize("file")
with open("file", "rb") as f:
    data = f.read()
encrypted = cipher.encrypt(data)
# below is the metadata about the file being sent
client.send("file.txt".encode())  # filename
print(f"Sending file size: {file_size}")  # Log the file size being sent
client.send(str(file_size).encode())  # Send the file size
client.sendall(encrypted)  # encrypted file data
client.send(b"<END>")  # end of file marker
