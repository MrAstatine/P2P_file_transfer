import os
import socket
import struct
import time
import tqdm
import hmac
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed

# import sys
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

CHUNK_SIZE = 4 * 1024 * 1024
PBKDF2_ROUNDS = 200_000
MAX_RETRIES = 3


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection lost during authentication")
        data += chunk
    return data


def authenticate_with_receiver(client, preset_code):
    """
    Perform challenge-response authentication with receiver.
    Returns True if successful, False otherwise.
    """
    key = preset_code.encode()

    try:
        challenge = recv_exact(client, 32)
        response = hmac.new(key, challenge, hashlib.sha256).digest()
        client.sendall(response)

        counter_challenge = recv_exact(client, 32)
        counter_response = hmac.new(key, counter_challenge, hashlib.sha256).digest()
        client.sendall(counter_response)

        status = client.recv(32)
        return status == b"AUTH_SUCCESS"
    except (ConnectionError, OSError):
        return False


def get_preset_code():
    preset_code = input("Enter preset code: ").strip()
    if not preset_code:
        print("❌ Error: Preset code cannot be empty.")
        raise SystemExit(1)
    return preset_code


def send_chunk(
    file_path,
    password,
    server_ip,
    server_port,
    preset_code,
    filename,
    chunk_id,
    offset,
    size,
    total_chunks,
):
    """Encrypt and send one chunk. Returns bytes sent on success, 0 on failure."""

    for attempt in range(1, MAX_RETRIES + 1):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.connect((server_ip, server_port))

            if not authenticate_with_receiver(client, preset_code):
                raise ConnectionError("Authentication failed with receiver")

            with open(file_path, "rb") as f:
                f.seek(offset)
                chunk_data = f.read(size)

            salt = get_random_bytes(16)
            key = PBKDF2(password.encode(), salt, dkLen=32, count=PBKDF2_ROUNDS)
            nonce = get_random_bytes(16)

            cipher = AES.new(key, AES.MODE_EAX, nonce)
            ciphertext, tag = cipher.encrypt_and_digest(chunk_data)

            client.sendall(struct.pack("!I", len(filename)))
            client.sendall(filename.encode())
            client.sendall(struct.pack("!I", chunk_id))
            client.sendall(struct.pack("!I", total_chunks))
            client.sendall(struct.pack("!I", len(ciphertext)))
            client.sendall(salt)
            client.sendall(nonce)
            client.sendall(tag)
            client.sendall(ciphertext)

            return len(chunk_data)

        except (
            ConnectionRefusedError,
            TimeoutError,
            BrokenPipeError,
            ConnectionError,
        ) as e:
            print(f"❌ Chunk {chunk_id}: {e} (attempt {attempt}/{MAX_RETRIES})")
            time.sleep(0.5 * attempt)
        except Exception as e:
            print(f"❌ Chunk {chunk_id}: {e} (attempt {attempt}/{MAX_RETRIES})")
            break
        finally:
            client.close()

    return 0


def send_file(file_path, password, server_ip, server_port, preset_code):
    """Send a file in encrypted chunks to the server."""

    filename = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
    threads = min(8, total_chunks)

    print(f"\n📤 Sending {filename}")
    print(f"📦 Total chunks: {total_chunks}, Threads: {threads}")

    progress = tqdm.tqdm(total=file_size, unit="B", unit_scale=True, unit_divisor=1024)
    bytes_sent = 0
    failed_chunks = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(
                send_chunk,
                file_path,
                password,
                server_ip,
                server_port,
                preset_code,
                filename,
                chunk_id,
                chunk_id * CHUNK_SIZE,
                min(CHUNK_SIZE, file_size - (chunk_id * CHUNK_SIZE)),
                total_chunks,
            ): chunk_id
            for chunk_id in range(total_chunks)
        }

        try:
            for future in as_completed(futures):
                chunk_id = futures[future]
                sent_now = future.result()
                if sent_now:
                    bytes_sent += sent_now
                    progress.update(sent_now)
                else:
                    failed_chunks.append(chunk_id)
        except KeyboardInterrupt:
            print("\n🛑 Cancelled by user. Waiting for active chunk sends to finish...")
        finally:
            progress.close()

    if failed_chunks:
        print(f"❌ Failed chunks: {sorted(failed_chunks)}")
        print(f"⚠️  File {filename} not fully sent.")
        return False

    print(f"✅ File {filename} sent successfully ({bytes_sent} bytes).")
    return True


if __name__ == "__main__":
    print("📤 Secure File Transfer - Sender")

    # Get server details
    server_ip = (
        input("Enter receiver's IP address (default: 172.20.10.3): ").strip()
        or "172.20.10.3"
    )
    server_port = int(
        input("Enter receiver's port (default: 1205): ").strip() or "1205"
    )
    PRESET_CODE = get_preset_code()

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
        send_file(file_path, password, server_ip, server_port, PRESET_CODE)

        continue_sending = input("\nSend another file? (y/n): ").strip().lower()
        if continue_sending != "y":
            break

    print("👋 File transfer session ended.")
