import socket
import struct
import sys
import os
import hmac
import hashlib
import threading
import contextlib
import time
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

chunks = {}
total_chunks_expected = None
filename_global = None
password_global = None
last_progress_ts = None
lock = threading.Lock()
PBKDF2_ROUNDS = 200_000
CHUNK_SIZE = 4 * 1024 * 1024


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


def reset_state():
    global chunks, total_chunks_expected, filename_global, password_global, last_progress_ts
    with lock:
        chunks = {}
        total_chunks_expected = None
        filename_global = None
        password_global = None
        last_progress_ts = None


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


def receive_chunk(client, preset_code):
    global total_chunks_expected, filename_global, password_global, last_progress_ts

    try:
        client.settimeout(10)

        if not authenticate_sender(client, preset_code):
            print("❌ Authentication failed for chunk connection")
            return

        filename_length = struct.unpack("!I", recv_exact(client, 4))[0]
        filename = recv_exact(client, filename_length).decode()
        filename = "received_" + filename

        chunk_id = struct.unpack("!I", recv_exact(client, 4))[0]
        total_chunks = struct.unpack("!I", recv_exact(client, 4))[0]
        chunk_size = struct.unpack("!I", recv_exact(client, 4))[0]

        salt = recv_exact(client, 16)
        nonce = recv_exact(client, 16)
        tag = recv_exact(client, 16)
        encrypted = recv_exact(client, chunk_size)

        if password_global is None:
            with lock:
                if password_global is None:
                    password_global = input(f"Enter password for {filename}: ").encode()

        key = PBKDF2(password_global, salt, dkLen=32, count=PBKDF2_ROUNDS)
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        decrypted = cipher.decrypt_and_verify(encrypted, tag)

        with lock:
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


def receive_one_file(server, preset_code, save_dir):
    """Receive a single chunked file session; returns True if successful."""
    reset_state()

    server.settimeout(2)
    idle_grace = 5

    while True:
        try:
            client, addr = server.accept()
        except socket.timeout:
            with lock:
                if total_chunks_expected and last_progress_ts:
                    if (time.time() - last_progress_ts) > idle_grace:
                        break
            continue
        except OSError:
            return False

        print(f"🔗 Connection from {addr}")
        worker = threading.Thread(target=receive_chunk, args=(client, preset_code))
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


def start_server(host="0.0.0.0", port=9999, save_dir=".", preset_code=None):
    """Start the server to receive chunked files."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(50)

    print(f"📡 Listening on {host}:{port} (waiting for sender)...")

    try:
        while True:
            ok = receive_one_file(server, preset_code, save_dir)

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


if __name__ == "__main__":
    print("📥 Secure File Transfer - Receiver")

    preset_code = get_preset_code()
    if not preset_code:
        print("❌ Error: Preset code cannot be empty.")
        sys.exit(1)

    try:
        host = input("Enter listening IP (default: 0.0.0.0): ").strip() or "0.0.0.0"
        port_str = input("Enter port (default: 9999): ").strip() or "9999"
        port = int(port_str)
    except ValueError:
        print("❌ Invalid port. Exiting.")
        sys.exit(1)

    save_dir = input("Enter save directory (default: current): ").strip() or "."
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    sys.exit(start_server(host, port, save_dir, preset_code))
