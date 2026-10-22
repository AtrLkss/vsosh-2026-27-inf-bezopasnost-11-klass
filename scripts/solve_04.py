"""Inspect the ASCII hexadecimal trailer of the supplied JPEG."""
from pathlib import Path

path = Path(__file__).resolve().parents[1] / "inputs" / "04-photo.jpg"
data = path.read_bytes()
eoi = data.rfind(b"\xff\xd9")
if eoi < 0:
    raise SystemExit("JPEG EOI marker not found")
trailer = data[eoi + 2:].strip()
decoded = bytes.fromhex(trailer.decode("ascii")).decode("ascii")
assert decoded.startswith("FLAG:vsosh{") and decoded.endswith("}")
print("JPEG EOI offset:", hex(eoi))
print("Hex trailer:", trailer.decode("ascii"))
print("Decoded:", decoded)
print("Flag:", decoded.removeprefix("FLAG:"))
