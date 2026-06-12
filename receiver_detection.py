import re
import socket
import subprocess


def detect_receiver_host() -> str:
    """local IP detection for the receiver UI."""
    host = "0.0.0.0"

    try:
        output = subprocess.check_output(
            ["ipconfig"],
            text=True,
            encoding="utf-8",
            errors="ignore",
        )

        matches = re.findall(r"IPv4 Address[^:]*:\s*([0-9.]+)", output)
        for detected in matches:
            if detected and not detected.startswith("127."):
                host = detected
                break
    except OSError:
        try:
            detected = socket.gethostbyname(socket.gethostname())
            if detected and not detected.startswith("127."):
                host = detected
        except OSError:
            pass

    return host
