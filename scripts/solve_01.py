"""Reverse the byte transformation, then check every byte and the checksum."""
TARGET = bytes.fromhex(
    "0b 6a d1 b7 36 85 54 95 c1 22 2f 6e ba e2 18 51 37 5e fb 32 cb 09"
)

def mix_byte(c, i):
    c ^= (0x2D + i * 7) & 0xFF
    c = ((c << 3) | (c >> 5)) & 0xFF
    return (c + 0x31 - i) & 0xFF

result = []
for i, y in enumerate(TARGET):
    rotated = (y - 0x31 + i) & 0xFF
    unmixed = ((rotated >> 3) | (rotated << 5)) & 0xFF
    result.append(unmixed ^ ((0x2D + i * 7) & 0xFF))
secret = bytes(result)
assert bytes(mix_byte(c, i) for i, c in enumerate(secret)) == TARGET
checksum = sum(c * (i + 3) for i, c in enumerate(secret))
assert checksum == 0x68CE
print("Flag:", secret.decode("ascii"))
print("Length:", len(secret))
print("Checksum:", hex(checksum))
print("Forward check: OK")
