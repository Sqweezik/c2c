#!/usr/bin/env python3.11
"""Final decryption step - take the recovered hex string and get the flag."""

hex_string = b'2faabd1b184becb15d02ddc60e9d0e110d7dea6231ec724ee13c555256df3e459088488669b550445add004811b5faca3a30aaffffae1cc864e0bb0be1ea5578aada2ad849b9dfc67104763450ccd3eb028482a4e2af1e2b4be634e0b85cc712c6b339ded761812d3428b3480c27b9bc3c40a372bc01446ba277bb91b8194cb38068c9f01bdc66c5efaefdf27a8f949267d4f67b4f58e632deea343fad5c9f38c95f801640af7113fc331e7db1d64bf1a619ef45407039b88da95a293984af67b671f6cef6d9539a879d92e863c4f4fcb020c211ad76a4e6587a1c543da5b5b5685030d953ad6bf363ce5dc9e0dab298cc21620508a252809896deff306953975858585858585858'

# Convert hex string to bytes (this is the padded f1 output)
f1_padded = bytes.fromhex(hex_string.decode())
print(f'f1 padded len: {len(f1_padded)}')

# Strip trailing X (0x58) padding
f1_output = f1_padded.rstrip(b'X')
print(f'f1 output len: {len(f1_output)} (stripped {len(f1_padded)-len(f1_output)} X bytes)')

# RSA decrypt
p = 147664276791346292682571421319406686359241754399192363821006199884945092580022219958301334075749180850207309189705243809810759538462765266279732154257815833960598593888800320403362705177170177360478717813006847116215161859872689668211196465545711864385921670982206874230822989249981487301669683093618161087983
q = 99177507796800546973798076338266659324570243536154689447130375225204840471663189780805139399475451471604437768162045843606335284989279517349483720482861496185773498446035333428515203588671045314390856023351738515175674106508856646629148551407435246485800068223960405384328787686720796309781817116525889575639
e = 65537
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

f1_int = int.from_bytes(f1_output, 'big')
decrypted_int = pow(f1_int, d, n)
print(f'Decrypted int: {decrypted_int}')

# Convert to bytes
byte_len = (decrypted_int.bit_length() + 7) // 8 or 1
decrypted_bytes = decrypted_int.to_bytes(byte_len, 'big')
print(f'Decrypted bytes ({len(decrypted_bytes)}): {decrypted_bytes.hex()}')

# XOR with key
xor_key = bytes.fromhex('37d5bc05382f92d0a098fc6fef0352474d291f2459688f63a630bf28d5a7a1507ed178e2f4baa8217f6e656c561e79b3f18d50a6da11cb57462df6d436f21113')
flag = bytes(decrypted_bytes[j] ^ xor_key[j % len(xor_key)] for j in range(len(decrypted_bytes)))

print(f'\nFLAG: {flag}')
try:
    print(f'FLAG (decoded): {flag.decode("utf-8")}')
except:
    print(f'FLAG (replace): {flag.decode("utf-8", errors="replace")}')
