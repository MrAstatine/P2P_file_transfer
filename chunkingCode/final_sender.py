import os
import socket
import struct
import time
import tqdm
import sys

from concurrent.futures import ThreadPoolExecutor  # for parallelism


from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

CHUNK_SIZE = 1024 * 1024*4 # 1MB chunk size for file transfer
PBKDF2_ROUNDS = 200_000
MAX_RETRIES = 3


# function to send a single chunk after encryption
def send_chunk(file_path, password, server_ip, server_port, filename, chunk_id, offset, size, total_chunks):
    """Encrypt and send one chunk. Returns bytes sent on success, 0 on failure."""

    for attempt in range(1, MAX_RETRIES + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((server_ip, server_port))

            with open(file_path, "rb") as f:
                f.seek(offset)
                chunk_data = f.read(size)

            salt = get_random_bytes(16)
            key = PBKDF2(password.encode(), salt, dkLen=32, count=PBKDF2_ROUNDS)
            nonce = get_random_bytes(16)

            cipher = AES.new(key, AES.MODE_EAX, nonce)
            ciphertext, tag = cipher.encrypt_and_digest(chunk_data)

            # metadata
            sock.sendall(struct.pack("!I", len(filename)))
            sock.sendall(filename.encode())

            sock.sendall(struct.pack("!I", chunk_id))
            sock.sendall(struct.pack("!I", total_chunks))
            sock.sendall(struct.pack("!I", len(ciphertext)))

            sock.sendall(salt)
            sock.sendall(nonce)
            sock.sendall(tag)

            # data
            sock.sendall(ciphertext)

            return len(chunk_data)

        except (ConnectionRefusedError, TimeoutError, BrokenPipeError) as e:
            print(f"❌ Chunk {chunk_id}: {e} (attempt {attempt}/{MAX_RETRIES})")
            time.sleep(0.5 * attempt)
        except Exception as e:
            print(f"❌ Chunk {chunk_id}: {e} (attempt {attempt}/{MAX_RETRIES})")
            break
        finally:
            sock.close()

    return 0


def send_file(file_path, password, server_ip, server_port):
    """
    Send a file with encryption to the server
    """

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
        futures = []

        for i in range(total_chunks):
            offset = i * CHUNK_SIZE
            size = min(CHUNK_SIZE, file_size - offset)

            futures.append(
                executor.submit(
                    send_chunk,
                    file_path,
                    password,
                    server_ip,
                    server_port,
                    filename,
                    i,
                    offset,
                    size,
                    total_chunks,
                )
            )

        try:
            for i, f in enumerate(futures):
                sent_now = f.result()
                if sent_now:
                    bytes_sent += sent_now
                    progress.update(sent_now)
                else:
                    failed_chunks.append(i)
        except KeyboardInterrupt:
            print("\n🛑 Cancelled by user. Waiting for active chunk sends to finish...")
            # Threads will exit soon because sockets will error/close
        finally:
            progress.close()

    if failed_chunks:
        print(f"❌ Failed chunks: {failed_chunks}")
        print(f"⚠️  File {filename} not fully sent.")
        return False

    print(f"✅ File {filename} sent successfully.\n")
    return True


def main():
    print("📤 Secure File Transfer - Sender")

    try:
        server_ip = (
            input("Enter receiver's IP address (default: 172.20.10.3): ").strip()
            or "172.20.10.3"
        )
        server_port_str = input("Enter receiver's port (default: 9999): ").strip() or "9999"
        server_port = int(server_port_str)
    except ValueError:
        print("❌ Invalid port. Exiting.")
        return 1

    try:
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
            ok = send_file(file_path, password, server_ip, server_port)
            if not ok:
                print("⚠️  Transfer incomplete. You can retry or exit.")

            continue_sending = input("\nSend another file? (y/n): ").strip().lower()
            if continue_sending != "y":
                break

    except KeyboardInterrupt:
        print("\n� Sender interrupted. Cleaning up...")
    finally:
        print("�👋 File transfer session ended.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
