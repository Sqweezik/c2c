#!/usr/bin/env python3
"""Decrypt the flag using RC4 with the extracted xorKeys"""
import base64

def rc4(key, data):
    """RC4 stream cipher"""
    # Key Scheduling Algorithm (KSA)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    # Pseudo-Random Generation Algorithm (PRGA)
    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        result.append(byte ^ K)
    return bytes(result)

# Extracted xorKeys from all 100 TokenInstance objects
xor_keys = bytes([94, 7, 73, 173, 201, 147, 209, 84, 192, 138, 59, 100, 219, 198, 190, 225,
                  55, 196, 121, 222, 122, 113, 36, 134, 119, 197, 242, 153, 3, 229, 46, 129,
                  211, 252, 208, 82, 233, 99, 55, 122, 146, 11, 182, 6, 161, 74, 31, 205,
                  201, 247, 216, 211, 226, 184, 90, 55, 1, 77, 137, 101, 196, 174, 35, 243,
                  36, 104, 16, 73, 25, 17, 139, 128, 68, 61, 162, 25, 194, 106, 193, 194,
                  11, 244, 202, 223, 90, 137, 131, 250, 172, 205, 141, 178, 178, 164, 20, 176,
                  31, 225, 220, 50])

# Base64 ciphertext found in stringliteral.json
b64_ciphertext = "m37Dm7dtQAEAClys4xu/S5CFIFsQnBwppswkOCORJq5byXYrSNUNF8gFh5ldu2Fv9jhEH2NRnZ1nLfDrsQ=="

ciphertext = base64.b64decode(b64_ciphertext)
print(f"Ciphertext ({len(ciphertext)} bytes): {ciphertext.hex()}")
print(f"Key ({len(xor_keys)} bytes): {xor_keys.hex()}")

# Try 1: Use xorKeys directly as the RC4 key (byte array)
plaintext = rc4(xor_keys, ciphertext)
print(f"\nAttempt 1 - RC4 with raw xorKeys bytes:")
print(f"  Hex: {plaintext.hex()}")
try:
    print(f"  Text: {plaintext.decode('utf-8')}")
except:
    print(f"  Text (lossy): {plaintext.decode('utf-8', errors='replace')}")

# Try 2: Use xorKeys as hex string for key
hex_key = xor_keys.hex().encode('utf-8')
plaintext2 = rc4(hex_key, ciphertext)
print(f"\nAttempt 2 - RC4 with hex-encoded xorKeys:")
print(f"  Hex: {plaintext2.hex()}")
try:
    print(f"  Text: {plaintext2.decode('utf-8')}")
except:
    print(f"  Text (lossy): {plaintext2.decode('utf-8', errors='replace')}")

# Try 3: Maybe the key is formed differently - xorKeys interpreted as UTF-8 string
# In C# string, byte values are chars. For IL2CPP, string is UTF-16.
# The "keyUtf8" parameter suggests it converts the string to UTF-8 bytes.
# If xorKeys is treated as raw data, each byte becomes a char in the string.
# For values < 128, UTF-8 encoding is same as raw byte.
# For values >= 128, UTF-8 encoding produces 2 bytes.
# Let me try using the raw bytes directly first (which is attempt 1).

# Try 4: Maybe only partial keys matters - look at how many flags there are
# The game has sprites Flag_1 through Flag_5, so maybe 5 flag pieces
# Each with a flagIndex that determines position 

# Try 5: What if DecryptFromBase64 is called differently?
# RC4.Crypt(string keyUtf8, byte[] data) converts key string to UTF-8 bytes
# then calls Crypt(byte[] key, byte[] data)
# So if xorKeys is passed as-is, attempt 1 should work

# But wait - the key might be the xorKeys bytes interpreted as a C# string
# In C#, bytes to string usually involves encoding. The bytes > 127 would be
# multi-byte in UTF-8, but as raw Latin-1 chars they'd be single bytes.
# Let me try treating xorKeys as Latin-1 → UTF-8 encoding
key_latin1 = bytes(xor_keys).decode('latin-1')
key_utf8 = key_latin1.encode('utf-8')
plaintext3 = rc4(key_utf8, ciphertext)
print(f"\nAttempt 3 - RC4 with Latin1→UTF-8 encoded xorKeys ({len(key_utf8)} bytes):")
print(f"  Hex: {plaintext3.hex()}")
try:
    print(f"  Text: {plaintext3.decode('utf-8')}")
except:
    print(f"  Text (lossy): {plaintext3.decode('utf-8', errors='replace')}")

# Try 6: Maybe it's just simple XOR (not RC4) with the ciphertext
# cipher ^ xorKeys[i % 100]
xored = bytes([ciphertext[i] ^ xor_keys[i % len(xor_keys)] for i in range(len(ciphertext))])
print(f"\nAttempt 4 - Simple XOR with xorKeys:")
print(f"  Hex: {xored.hex()}")
try:
    print(f"  Text: {xored.decode('utf-8')}")
except:
    print(f"  Text (lossy): {xored.decode('utf-8', errors='replace')}")

print("\n\nDone.")
