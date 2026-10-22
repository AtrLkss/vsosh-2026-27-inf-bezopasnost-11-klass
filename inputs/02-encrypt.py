def encrypt(data: bytes):
    encrypted = []

    for x in data:
        y = (73 * x + 41) % 257
        encrypted.append(y)

    result = []

    for i in range(0, len(encrypted), 4):
        block = encrypted[i : i + 4]
        result.extend(block[::-1])

    return result
