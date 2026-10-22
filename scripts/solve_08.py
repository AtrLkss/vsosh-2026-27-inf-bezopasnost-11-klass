"""Parse this PCAP's IPv4/TCP packets and recover numbered HTTP fragments.

This capture contains whole /upload HTTP requests in individual TCP payloads.
A general HTTP analyzer must also handle TCP reassembly and retransmissions.
"""
from pathlib import Path
from urllib.parse import parse_qs
import base64
import struct

path = Path(__file__).resolve().parents[1] / "inputs" / "08-traffic.pcap"
capture = path.read_bytes()
if capture[:4] != b"\xd4\xc3\xb2\xa1":
    raise SystemExit("Expected this task's little-endian PCAP")
linktype = struct.unpack_from("<I", capture, 20)[0]
assert linktype == 228  # LINKTYPE_IPV4: packets start with an IPv4 header.
position = 24
chunks = {}
arrival_order = []
expected_total = None
while position < len(capture):
    if position + 16 > len(capture):
        raise ValueError("Truncated PCAP record header")
    _, _, captured_length, _ = struct.unpack_from("<IIII", capture, position)
    position += 16
    packet = capture[position:position+captured_length]
    position += captured_length
    if len(packet) != captured_length:
        raise ValueError("Truncated PCAP packet")
    if len(packet) < 20 or packet[0] >> 4 != 4 or packet[9] != 6:
        continue
    ip_length = (packet[0] & 15) * 4
    total_length = int.from_bytes(packet[2:4], "big")
    tcp_length = (packet[ip_length + 12] >> 4) * 4
    payload = packet[ip_length + tcp_length:total_length]
    if not payload.startswith(b"POST /upload HTTP/1.1\r\n"):
        continue
    headers, _, body = payload.partition(b"\r\n\r\n")
    content_length = next(int(line.split(b":", 1)[1]) for line in headers.split(b"\r\n")
                          if line.lower().startswith(b"content-length:"))
    if len(body) < content_length:
        raise ValueError("Request spans packets; TCP reassembly is needed")
    form = parse_qs(body[:content_length].decode("ascii").strip())
    number = int(form["id"][0])
    total = int(form["total"][0])
    piece = form["data"][0]
    if number in chunks and chunks[number] != piece:
        raise ValueError("Conflicting duplicate fragment")
    if expected_total is not None and expected_total != total:
        raise ValueError("Conflicting fragment counts")
    expected_total = total
    chunks[number] = piece
    arrival_order.append(number)
assert expected_total is not None
assert set(chunks) == set(range(1, expected_total + 1))
encoded = "".join(chunks[i] for i in range(1, expected_total + 1))
decoded = base64.b64decode(encoded, validate=True)
assert base64.b64encode(decoded).decode("ascii") == encoded
print("Link type:", linktype, "(IPv4)")
print("Arrival order:", arrival_order)
for number in sorted(chunks):
    print(f"Part {number}/{expected_total}: {chunks[number]}")
print("Base64:", encoded)
print("Flag:", decoded.decode("ascii"))
print("All parts present; Base64 round trip: OK")
