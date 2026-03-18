import socket
import struct
import tqdm
import sys
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# Preset authentication code
PRESET_CODE = "CN_SECURE_1234"


def authenticate():
    """
    Prompt for and validate the preset code.
    Returns True if authentication succeeds, False otherwise.
    """
    print("🔐 Authentication required")
    user_code = input("Enter preset code: ").strip()
    if user_code != PRESET_CODE:
        print("❌ Authentication failed: Incorrect preset code")
        return False
    print("✅ Authentication successful")
    return True


def receive_file(client, save_dir="."):
    """
    Receive and decrypt a file from the client
    """
    # Receive filename details
    filename_length = struct.unpack("I", client.recv(4))[0]
    filename = client.recv(filename_length).decode()
    file_size = struct.unpack("Q", client.recv(8))[0]

    print(f"\n⬇ Receiving file: {filename} ({file_size} bytes)")

    # Receive the salt and nonce
    salt = client.recv(16)
    nonce = client.recv(16)

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
        decrypted_data = cipher.decrypt(file_bytes)

        # Save the file
        save_path = os.path.join(save_dir, "received_" + filename)
        with open(save_path, "wb") as f:
            f.write(decrypted_data)
        print(f"✅ File received and saved successfully to {save_path}")
        return True
    except Exception as e:
        print(f"❌ Decryption error: {e}")
        print("This could be due to an incorrect password.")
        return False


def start_server(host="0.0.0.0", port=9999, save_dir="."):
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
            print(f"✅ Connection from {addr} established.")

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

    # Authenticate before proceeding
    if not authenticate():
        print("🚫 Exiting due to failed authentication")
        sys.exit(1)

    # Get server settings
    host = (
        input("Enter listening IP (default: 0.0.0.0 for all interfaces): ").strip()
        or "0.0.0.0"
    )
    port = int(input("Enter port to listen on (default: 9999): ").strip() or "9999")

    # Get save directory
    save_dir = (
        input("Enter directory to save files (default: current directory): ").strip()
        or "."
    )
    if not os.path.exists(save_dir):
        try:
            os.makedirs(save_dir)
            print(f"✅ Created directory: {save_dir}")
        except:
            print(f"❌ Error creating directory: {save_dir}")
            print("Using current directory instead.")
            save_dir = "."

    # Start the server
    start_server(host, port, save_dir)
