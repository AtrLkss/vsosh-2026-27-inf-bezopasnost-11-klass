"""Read task 10's embedded AES-GCM data; never execute the EXE."""
from pathlib import Path
import argparse
import hashlib
from Crypto.Cipher import AES

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("exe", type=Path)
args = parser.parse_args()
data = args.exe.read_bytes()
digest = hashlib.sha256(data).hexdigest()
if len(data) != 2656256 or digest != "cd7e901210cc5e163f95cfa55950186275f22a1c5d7e146aaef2d72a254da674":
    raise SystemExit("Different binary: these offsets do not apply to this file")
key = data[0x1fa8cd:0x1fa8ed]
nonce = data[0x1f0a10:0x1f0a1c]
encrypted = data[0x1fa8a0:0x1fa8cd]
plaintext = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(
    encrypted[:-16], encrypted[-16:]
)
print("SHA-256:", digest)
print("AES-GCM authentication tag: valid")
print("Flag:", plaintext.decode("utf-8"))
