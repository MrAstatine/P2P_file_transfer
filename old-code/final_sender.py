import os
import socket
import struct
import tqdm

# import sys
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes


def send_file(file_path, password, server_ip, server_port):
    """
    Send a file with encryption to the server
    """
    # Convert string password to bytes
    password_bytes = password.encode()

    # Generate salt and derive key
    salt = get_random_bytes(16)
    key = PBKDF2(password_bytes, salt, dkLen=32)

    # Generate nonce and create cipher
    nonce = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX, nonce)

    # Create socket and connect
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((server_ip, server_port))
    except ConnectionRefusedError:
        print(
            "❌ Error: Cannot connect to the server. Make sure the receiver is running."
        )
        return False

    # Get filename from path and file size
    filename = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)

    # Send filename and file size
    client.send(struct.pack("I", len(filename)))
    client.send(filename.encode())
    client.send(struct.pack("Q", file_size))

    # Send salt and nonce for decryption
    client.send(salt)
    client.send(nonce)

    # Read file, encrypt and send
    with open(file_path, "rb") as f:
        data = f.read()
        encrypted = cipher.encrypt(data)

    # Show progress
    progress = tqdm.tqdm(total=file_size, unit="B", unit_scale=True, unit_divisor=1024)

    try:
        client.sendall(encrypted)
        progress.update(file_size)
        print(f"✅ File {filename} sent successfully with encryption.")
        return True
    except BrokenPipeError:
        print("❌ Connection lost! Receiver closed unexpectedly.")
        return False
    finally:
        client.close()


if __name__ == "__main__":
    print("📤 Secure File Transfer - Sender")

    # Get server details
    server_ip = (
        input("Enter receiver's IP address (default: 172.20.10.3): ").strip()
        or "172.20.10.3"
    )
    server_port = int(
        input("Enter receiver's port (default: 9999): ").strip() or "9999"
    )

    while True:
        file_path = input(
            "\nEnter the path to the file to send (or 'exit' to quit): "
        ).strip()
        if file_path.lower() == "exit":
            break

        if not os.path.exists(file_path):
            print(f"❌ Error: File '{file_path}' not found.")
            continue

        password = input("Enter unique password for this file: ").strip()
        if not password:
            print("❌ Error: Password cannot be empty.")
            continue

        print(f"\n📤 Sending {os.path.basename(file_path)}...")
        send_file(file_path, password, server_ip, server_port)

        continue_sending = input("\nSend another file? (y/n): ").strip().lower()
        if continue_sending != "y":
            break

    print("👋 File transfer session ended.")
