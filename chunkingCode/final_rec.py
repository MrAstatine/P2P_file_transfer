import socket
import struct
import threading
import sys
import os
import contextlib
import time

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# 🔹 Global storage
chunks = {}
total_chunks_expected = None
filename_global = None
lock = threading.Lock()
PBKDF2_ROUNDS = 200_000
password_global = None
last_progress_ts = None


def reset_state():
    global chunks, total_chunks_expected, filename_global, password_global, last_progress_ts
    with lock:
        chunks = {}
        total_chunks_expected = None
        filename_global = None
        password_global = None
        last_progress_ts = None


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection lost")
        data += chunk
    return data


# 🔹 Preset authentication code
PRESET_CODE = "CN_SECURE_1234"


def authenticate():
    print("🔐 Authentication required")
    user_code = input("Enter preset code: ").strip()
    if user_code != PRESET_CODE:
        print("❌ Authentication failed")
        return False
    print("✅ Authentication successful")
    return True


# 🔹 Handle one chunk (one connection)
def receive_chunk(client):
    global total_chunks_expected, filename_global, password_global, last_progress_ts

    try:
        client.settimeout(10)
        # --- metadata ---
        filename_length = struct.unpack("!I", recv_exact(client, 4))[0]
        filename = recv_exact(client, filename_length).decode()
        filename = "received_" + filename  # prefix to avoid overwriting existing files

        chunk_id = struct.unpack("!I", recv_exact(client, 4))[0]
        total_chunks = struct.unpack("!I", recv_exact(client, 4))[0]
        chunk_size = struct.unpack("!I", recv_exact(client, 4))[0]

        # --- crypto ---
        salt = recv_exact(client, 16)
        nonce = recv_exact(client, 16)
        tag = recv_exact(client, 16)

        encrypted = recv_exact(client, chunk_size)

        # prompt for password once, on first chunk arrival
        if password_global is None:
            with lock:
                if password_global is None:
                    password_global = input(f"Enter password for {filename}: ").encode()

        key = PBKDF2(password_global, salt, dkLen=32, count=PBKDF2_ROUNDS)
        cipher = AES.new(key, AES.MODE_EAX, nonce)

        decrypted = cipher.decrypt_and_verify(encrypted, tag)

        # --- store chunk ---
        with lock:
            # Ignore duplicate chunks from retries
            if chunk_id not in chunks:
                chunks[chunk_id] = decrypted
                total_chunks_expected = total_chunks
                filename_global = filename
                last_progress_ts = time.time()

            print(f"⬇ Received chunk {chunk_id + 1}/{total_chunks}")

    except Exception as e:
        print(f"❌ Error receiving chunk: {e}")

    finally:
        client.close()


# 🔹 Server
def receive_one_file(server, save_dir):
    """Receive a single file session; returns True if successful."""
    reset_state()

    server.settimeout(2)
    idle_grace = 5  # seconds without new chunks after first chunk

    while True:
        try:
            client, addr = server.accept()
        except socket.timeout:
            with lock:
                if total_chunks_expected:
                    if (
                        last_progress_ts
                        and (time.time() - last_progress_ts) > idle_grace
                    ):
                        break
            continue
        except OSError:
            return False

        print(f"🔗 Connection from {addr}")

        worker = threading.Thread(target=receive_chunk, args=(client,))
        worker.daemon = True
        worker.start()

        with lock:
            if total_chunks_expected and len(chunks) == total_chunks_expected:
                break

    if total_chunks_expected and len(chunks) == total_chunks_expected:
        output_path = os.path.join(save_dir, filename_global)

        with open(output_path, "wb") as f:
            for i in range(total_chunks_expected):
                f.write(chunks[i])

        print(f"✅ File received and saved to: {output_path}")
        return True

    missing = []
    if total_chunks_expected:
        missing = [i for i in range(total_chunks_expected) if i not in chunks]

    if missing:
        print(
            f"⚠️  Incomplete transfer. Missing chunks: {missing[:10]}"
            + (" ..." if len(missing) > 10 else "")
        )
    else:
        print("⚠️  Incomplete transfer. File not reconstructed.")
    return False


def start_server(host="0.0.0.0", port=9999, save_dir="."):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(50)  # allow many simultaneous connections

    print(f"📡 Listening on {host}:{port} (waiting for sender)...")

    try:
        while True:
            ok = receive_one_file(server, save_dir)

            if ok:
                print("🎉 Transfer complete.")
            else:
                print("⚠️  Transfer ended without full success.")

            choice = input("Receive another file? (y/n): ").strip().lower()
            if choice != "y":
                break
            print("📡 Ready for next file. Waiting for sender...")

    except KeyboardInterrupt:
        print("\n🛑 Server stopped")

    finally:
        with contextlib.suppress(Exception):
            server.close()
        print("👋 Receiver closed")


# 🔹 Main
def main():
    print("📥 Secure File Transfer - Receiver")

    if not authenticate():
        return 1

    try:
        host = input("Enter listening IP (default: 0.0.0.0): ").strip() or "0.0.0.0"
        port_str = input("Enter port (default: 9999): ").strip() or "9999"
        port = int(port_str)
    except ValueError:
        print("❌ Invalid port. Exiting.")
        return 1

    save_dir = input("Enter save directory (default: current): ").strip() or "."
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    try:
        start_server(host, port, save_dir)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
