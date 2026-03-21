import socket
import struct
import tqdm
import sys
import os
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection lost")
        data += chunk
    return data


def get_preset_code():
    """Get and store the preset code for this receiver session."""
    print("🔐 Setup Authentication")
    code = input("Enter preset code for this session: ").strip()
    return code


def authenticate_sender(client, preset_code):
    """
    Perform challenge-response authentication with sender.
    Returns True if authenticated, False otherwise.
    """
    key = preset_code.encode()

    try:
        challenge = get_random_bytes(32)
        client.sendall(challenge)

        received_response = recv_exact(client, 32)
        expected_response = hmac.new(key, challenge, hashlib.sha256).digest()
        if not hmac.compare_digest(received_response, expected_response):
            client.sendall(b"AUTH_FAIL")
            return False

        counter_challenge = get_random_bytes(32)
        client.sendall(counter_challenge)

        received_counter = recv_exact(client, 32)
        expected_counter = hmac.new(key, counter_challenge, hashlib.sha256).digest()
        if not hmac.compare_digest(received_counter, expected_counter):
            client.sendall(b"AUTH_FAIL")
            return False

        client.sendall(b"AUTH_SUCCESS")
        return True
    except (ConnectionError, OSError):
        try:
            client.sendall(b"AUTH_FAIL")
        except OSError:
            pass
        return False


def receive_file(client, save_dir="."):
    """
    Receive and decrypt a file from the client
    """
    # Receive filename details
    filename_length = struct.unpack("I", recv_exact(client, 4))[0]
    filename = recv_exact(client, filename_length).decode()
    file_size = struct.unpack("Q", recv_exact(client, 8))[0]

    print(f"\n⬇ Receiving file: {filename} ({file_size} bytes)")

    # Receive the salt and nonce
    salt = recv_exact(client, 16)
    nonce = recv_exact(client, 16)
    tag = recv_exact(client, 16)

    # Get password for this specific file
    password = input(f"Enter password for decrypting {filename}: ").strip().encode()

    # Derive the key using the provided password
    key = PBKDF2(password, salt, dkLen=32)

    # Create the cipher for decryption
    cipher = AES.new(key, AES.MODE_EAX, nonce)

    # Receive and decrypt the file
    file_bytes = b""
    progress = tqdm.tqdm(total=file_size, unit="B", unit_scale=True, unit_divisor=1024)

    while len(file_bytes) < file_size:
        chunk = client.recv(min(1024, file_size - len(file_bytes)))
        if not chunk:
            break
        file_bytes += chunk
        progress.update(len(chunk))

    # Check if we received the complete file
    if len(file_bytes) != file_size:
        print(f"❌ Error: Expected {file_size} bytes but got {len(file_bytes)} bytes.")
        return False

    try:
        # Try to decrypt
        decrypted_data = cipher.decrypt_and_verify(file_bytes, tag)

        # Save the file
        save_path = os.path.join(save_dir, "received_" + filename)
        with open(save_path, "wb") as f:
            f.write(decrypted_data)
        print(f"✅ File received and saved successfully to {save_path}")
        return True
    except ValueError:
        print("❌ File tampered or wrong password!")
        return False


def start_server(host="0.0.0.0", port=9999, save_dir=".", preset_code=None):
    """
    Start the server to receive multiple files
    """
    # Initialize socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(1)

    print(f"📡 Server started on {host}:{port}. Waiting for connections...")

    try:
        while True:
            client, addr = server.accept()
            print(f"🔌 Connection from {addr}")

            if not authenticate_sender(client, preset_code):
                print(f"❌ Authentication failed from {addr}")
                client.close()
                continue

            print(f"✅ Sender authenticated from {addr}")

            # Receive a file
            receive_file(client, save_dir)

            # Close the connection
            client.close()

            # Ask if more files are expected
            continue_receiving = input("\nWait for more files? (y/n): ").strip().lower()
            if continue_receiving != "y":
                break

            print("\n📡 Waiting for next file...")

    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user.")
    finally:
        server.close()
        print("👋 File receiver session ended.")


if __name__ == "__main__":
    print("📥 Secure File Transfer - Receiver")

    preset_code = get_preset_code()
    if not preset_code:
        print("❌ Error: Preset code cannot be empty.")
        sys.exit(1)

    # Get server settings
    host = (
        input("Enter listening IP (default: 0.0.0.0 for all interfaces): ").strip()
        or "0.0.0.0"
    )
    port = int(input("Enter port to listen on (default: 1205): ").strip() or "1205")

    # Get save directory
    save_dir = (
        input("Enter directory to save files (default: current directory): ").strip()
        or "."
    )
    if not os.path.exists(save_dir):
        try:
            os.makedirs(save_dir)
            print(f"✅ Created directory: {save_dir}")
        except Exception:
            print(f"❌ Error creating directory: {save_dir}")
            print("Using current directory instead.")
            save_dir = "."

    # Start the server
    start_server(host, port, save_dir, preset_code)
