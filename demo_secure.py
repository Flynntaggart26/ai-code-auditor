"""Clean example: passes SafeCode AI with score 100/100 (A)."""
import hashlib
import secrets
import subprocess
import tempfile


def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


def make_token() -> str:
    return secrets.token_hex(16)


def list_dir(path: str) -> str:
    result = subprocess.run(["ls", path], shell=False, capture_output=True, text=True)
    return result.stdout


def temp_file():
    fd, path = tempfile.mkstemp()
    return fd, path
