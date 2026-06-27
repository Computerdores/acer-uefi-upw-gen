#!/usr/bin/env python3
import hashlib
import crcmod
from Crypto.Cipher import AES
import sys

# reversed crc64 ecma182
crc64 = crcmod.mkCrcFun(0x142F0E1EBA9EA3693, rev=True, initCrc=0, xorOut=0)

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def shuffle32(data: bytes) -> bytes:
    return bytes([data[(i * (data[9] * 2 + 1)) % len(data)] for i in range(len(data))])

def matrix_multiply(a: bytes, b: bytes) -> bytes:
    """Multiply a 4x8 matrix with an 8x4 matrix to yield a 4x4 matrix. Elements are 8bit values with wrap around addition."""
    result = bytearray(16)
    for r in range(4):
        for c in range(4):
            acc = 0
            for k in range(8):
                acc += a[8 * r + k] * b[4 * k + c]
            result[4 * r + c] = acc & 0xFF
    return bytes(result)


def transform0(data: bytes) -> bytes:
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[(3 - r) * 4 + c] = data[c * 4 + r]
    return bytes(out)

def transform1(data: bytes) -> bytes:
    out = bytearray(len(data))
    for r in range(4):
        for c in range(4):
            out[r * 4 + c] = data[(3 - c) * 4 + r]
    return bytes(out)

def transform2(data: bytes) -> bytes:
    out = bytearray(len(data))
    for i in range(4):
        for j in range(4):
            src = i * 4 + ((i + j) % 4)
            out[i * 4 + j] = (data[src] + i) & 0xFF
    return bytes(out)

def transform3(data: bytes) -> bytes:
    diag_xor = 0
    for i in range(4):
        diag_xor ^= data[i * 4 + i]
    anti_diag_xor = 0
    for i in range(4):
        anti_diag_xor ^= data[i * 4 + (3 - i)]

    out = bytearray(len(data))
    for pos in range(len(data)):
        key = anti_diag_xor if (pos % 2 == 1) else diag_xor
        out[pos] = data[pos] ^ key
    return bytes(out)

def transform4(data: bytes) -> bytes:
    out = bytearray(len(data))
    for k in range(len(data)):
        a = data[k]
        b = data[(k + 1) % len(data)]
        if a > b:
            out[k] = a ^ b
        else:
            out[k] = (~a) & 0xFF
    return bytes(out)

def transform5(data: bytes) -> bytes:
    out = bytearray(len(data))
    for idx in range(4):
        positions = range(idx, len(data), 4)
        col_xor = 0
        for p in positions:
            col_xor ^= data[p]
        for p in positions:
            out[p] = (col_xor * data[p]) & 0xFF
    return bytes(out)

TRANSFORMS = [transform0, transform1, transform2, transform3, transform4, transform5]


def aes_shuffle(hash: bytes) -> bytes:
    # print(f"AES.hash = {hash.hex()}")
    plaintext = shuffle32(hash[:])[:16]
    # print(f"AES.plaintext = {plaintext.hex()}")
    m = matrix_multiply(hash[:], hash[:])
    # print(f"AES.multiplied = {m.hex()}", flush=True)
    key = TRANSFORMS[hash[8] % 6](m)
    # print(f"AES.key = {key.hex()}")
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def generate_upw(key: str) -> str:
    h = sha256(key.encode()) # validated on multiple examples
    a = aes_shuffle(h)
    c = crc64(a).to_bytes(8) # validated on multiple examples
    return c.hex().upper()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        import json
        with open("correct_unlock_passwords.json", "r") as f:
            valid = json.load(f)
        for key in valid:
            assert generate_upw(key) == valid[key], f"Failed for key {key}, upw {valid[key]}"
        print("ALL TESTS PASSED")
    else:
        key = input("Enter key: ")
        upw = generate_upw(key)
        print(f'Unlock Password for key "{key}": "{upw}"')
