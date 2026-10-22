"""Undo block reversal and the affine transformation modulo 257."""
from pathlib import Path
import ast

path = Path(__file__).resolve().parents[1] / "inputs" / "02-ciphertext.txt"
encrypted = ast.literal_eval(path.read_text(encoding="utf-8"))

def reverse_blocks(values):
    return [v for i in range(0, len(values), 4) for v in values[i:i+4][::-1]]

inverse = pow(73, -1, 257)
secret = bytes(((y - 41) * inverse) % 257 for y in reverse_blocks(encrypted))
encoded_again = reverse_blocks([(73 * x + 41) % 257 for x in secret])
assert encoded_again == encrypted
print("Inverse of 73 modulo 257:", inverse)
print("Flag:", secret.decode("ascii"))
print("Forward check: OK")
