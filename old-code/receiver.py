import socket
import tqdm
from Crypto.Cipher import AES

key = b"TheProjectSubmit"
nonce = b"tHEpROJECTsUBMIT"
cipher = AES.new(key, AES.MODE_EAX, nonce)
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP socket
server.bind(("localhost", 9999))  # bind to local host and port
server.listen()
# we are going to transfer only once and then end connection.
# we are not going to listen continously
client, addr = server.accept()
file_name = client.recv(1024).decode()
print(file_name)
file_size_bytes = client.recv(1024)
print(f"Received file size data: {file_size_bytes}")  # Log the received file size data
try:
    file_size = file_size_bytes.decode()
except UnicodeDecodeError:
    print("Received invalid file size data.")
    client.close()
    server.close()
    exit(1)
print(file_size)
file = open(file_name, "wb")
done = False
file_bytes = b""
progress = tqdm.tqdm(unit="B", unit_scale=True, unit_divisor=1000, total=int(file_size))
while not done:
    data = client.recv(1024)
    if file_bytes[-5:] == b"<END>":
        done = True
    else:
        file_bytes += data
    progress.update(1024)
file.write(cipher.decrypt(file_bytes[:-5]))
file.close()
client.close()
server.close()
