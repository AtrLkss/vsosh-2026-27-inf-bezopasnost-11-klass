"""Read task 9's embedded AES-GCM data; never execute the EXE."""
from pathlib import Path
import argparse
import hashlib
from Crypto.Cipher import AES

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("exe", type=Path)
args = parser.parse_args()
data = args.exe.read_bytes()
digest = hashlib.sha256(data).hexdigest()
if len(data) != 4078080 or digest != "61f2080ae2860f6e7bf437884467eae1ceb2945fed55571425baa8099639bacb":
    raise SystemExit("Different binary: these offsets do not apply to this file")
key = data[0x30989a:0x3098ba]
nonce = data[0x30bdd0:0x30bddc]
encrypted = data[0x30bda0:0x30bdd0]
plaintext = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(
    encrypted[:-16], encrypted[-16:]
)
print("SHA-256:", digest)
print("AES-GCM authentication tag: valid")
print("Flag:", plaintext.decode("utf-8"))
