#!/usr/bin/env python3
"""Extract all token keys and find/decrypt the flag from Unity CTF game."""
import UnityPy
import os
import struct
import json

ASSET_DIR = r"C:\Users\sq\Desktop\c2c\capturetheflag\extracted\assets\bin\Data"
DATA_UNITY3D = os.path.join(ASSET_DIR, "data.unity3d")
IL2CPP_DIR = r"C:\Users\sq\Desktop\c2c\capturetheflag\il2cpp_output"
METADATA_PATH = os.path.join(ASSET_DIR, "Managed", "Metadata", "global-metadata.dat")
LIBIL2CPP = r"C:\Users\sq\Desktop\c2c\capturetheflag\extracted\lib\arm64-v8a\libil2cpp.so"

# MonoScript PathIDs
TOKENINSTANCE_SCRIPT_PID = 1431

def parse_mono_header(raw):
    if len(raw) < 32:
        return None
    go_pid = struct.unpack_from('<q', raw, 4)[0]
    script_pid = struct.unpack_from('<q', raw, 20)[0]
    name_len = struct.unpack_from('<i', raw, 28)[0]
    name_end = 32 + name_len
    custom_start = (name_end + 3) & ~3
    return go_pid, script_pid, custom_start

# ============================================================================
# STEP 1: Extract all 100 token keyIndex/keyValue pairs
# ============================================================================
print("="*80)
print("STEP 1: EXTRACTING TOKEN KEYS")
print("="*80)

env = UnityPy.load(DATA_UNITY3D)

xor_keys = [0] * 100  # Initialize to zeros
token_pairs = []

for obj in env.objects:
    if obj.type.name != "MonoBehaviour":
        continue
    try:
        raw = obj.get_raw_data()
        parsed = parse_mono_header(raw)
        if not parsed:
            continue
        go_pid, script_pid, custom_start = parsed
        if script_pid != TOKENINSTANCE_SCRIPT_PID:
            continue
        
        cd = raw[custom_start:]
        # TokenInstance serialized fields:
        # 0-11: tokenCollectAudio PPtr (12 bytes)
        # 12-15: randomAnimationStartTime bool (4 bytes aligned)
        # 16-19: idleAnimation count (4 bytes)
        # 20+: idleAnimation PPtrs (count * 12 bytes)
        # After idle: collectedAnimation count (4 bytes)
        # After collected sprites: more PPtrs
        # Last 8 bytes: keyIndex (4) + keyValue (4)
        
        # Parse from end - last 8 bytes are keyIndex + keyValue
        key_index = struct.unpack_from('<i', cd, len(cd) - 8)[0]
        key_value = struct.unpack_from('<i', cd, len(cd) - 4)[0]
        
        token_pairs.append((obj.path_id, key_index, key_value))
        
        if 0 <= key_index < 100:
            xor_keys[key_index] = key_value & 0xFF
        
    except Exception as e:
        pass

token_pairs.sort(key=lambda x: x[1])  # Sort by keyIndex

print(f"Found {len(token_pairs)} TokenInstance objects")
print(f"\nToken keyIndex -> keyValue mappings:")
for pid, ki, kv in token_pairs:
    print(f"  PathID={pid}: keyIndex={ki}, keyValue={kv} (0x{kv:02x})")

print(f"\nReconstructed xorKeys array (100 bytes):")
print(f"  {xor_keys}")
print(f"  Hex: {bytes(xor_keys).hex()}")

# Check which indices are covered
covered = set(ki for _, ki, _ in token_pairs)
missing = [i for i in range(100) if i not in covered]
print(f"\n  Covered indices: {sorted(covered)}")
print(f"  Missing indices: {missing}")

# ============================================================================
# STEP 2: Search for encrypted flag text
# ============================================================================
print("\n" + "="*80)
print("STEP 2: SEARCHING FOR ENCRYPTED FLAG TEXT")
print("="*80)

# 2a. Search string literals from stringliteral.json
print("\n--- StringLiteral.json search ---")
strlits_path = os.path.join(IL2CPP_DIR, "stringliteral.json")
with open(strlits_path, 'r', encoding='utf-8') as f:
    strlits = json.load(f)

print(f"Total string literals: {len(strlits)}")

# Look for strings that when XOR'd with our keys give "c2c{" 
# encrypted[i] = plaintext[i] XOR key[i]
# For plaintext starting with "c2c{": 0x63, 0x32, 0x63, 0x7b
c2c_prefix_bytes = b"\x63\x32\x63\x7b"

# Compute expected encrypted prefix
expected_enc = bytes([c2c_prefix_bytes[i] ^ xor_keys[i] for i in range(4)])
expected_enc_hex = expected_enc.hex()
print(f"\nExpected encrypted prefix for 'c2c{{': hex={expected_enc_hex}")
print(f"  Raw bytes: {list(expected_enc)}")

# For each string literal, check if:
# 1. Length is reasonable (20-100 chars)  
# 2. First 4 bytes match expected encrypted prefix
# 3. Last byte XOR'd gives '}'
candidates = []
for entry in strlits:
    value = entry.get("value", "")
    addr = entry.get("address", "")
    
    if not value:
        continue
    
    # Encode to bytes
    try:
        vbytes = value.encode('utf-8')
    except:
        continue
    
    if len(vbytes) < 4 or len(vbytes) > 100:
        continue
    
    # Check prefix
    if vbytes[:4] == expected_enc:
        # Try full decryption
        decrypted = bytes([vbytes[i] ^ xor_keys[i % 100] for i in range(len(vbytes))])
        dec_str = decrypted.decode('ascii', errors='replace')
        candidates.append((addr, value, dec_str))
        print(f"  MATCH: addr={addr}, encrypted={value!r}, decrypted={dec_str!r}")
    
    # Also check if decrypted ends with '}'
    if len(vbytes) > 4:
        last_byte_dec = vbytes[-1] ^ xor_keys[(len(vbytes)-1) % 100]
        first_four_dec = bytes([vbytes[i] ^ xor_keys[i % 100] for i in range(min(4, len(vbytes)))])
        if first_four_dec == c2c_prefix_bytes and last_byte_dec == ord('}'):
            decrypted = bytes([vbytes[i] ^ xor_keys[i % 100] for i in range(len(vbytes))])
            dec_str = decrypted.decode('ascii', errors='replace')
            if (addr, value, dec_str) not in candidates:
                candidates.append((addr, value, dec_str))
                print(f"  FULL MATCH: addr={addr}, encrypted={value!r}, decrypted={dec_str!r}")

# Also try brute force: decrypt every string and check if result starts with c2c{
print("\n--- Brute force decryption of all string literals ---")
for entry in strlits:
    value = entry.get("value", "")
    addr = entry.get("address", "")
    if not value or len(value) < 4 or len(value) > 100:
        continue
    try:
        vbytes = value.encode('latin-1')  # Use latin-1 to preserve bytes
    except:
        continue
    
    decrypted = bytes([vbytes[i] ^ xor_keys[i % 100] for i in range(len(vbytes))])
    try:
        dec_str = decrypted.decode('ascii')
        if dec_str.startswith('c2c{') and dec_str.endswith('}'):
            print(f"  FLAG FOUND! addr={addr}")
            print(f"    Encrypted: {value!r}")
            print(f"    Decrypted: {dec_str}")
    except:
        pass

# 2b. Search global-metadata.dat for potential flag text
print("\n--- Global-metadata.dat search ---")
with open(METADATA_PATH, 'rb') as f:
    metadata = f.read()
print(f"Metadata size: {len(metadata)} bytes")

# Search for the expected encrypted prefix in metadata
enc_prefix = expected_enc
for i in range(len(metadata) - len(enc_prefix)):
    if metadata[i:i+len(enc_prefix)] == enc_prefix:
        # Found potential match, try to decrypt a chunk
        chunk = metadata[i:i+100]
        decrypted = bytes([chunk[j] ^ xor_keys[j % 100] for j in range(len(chunk))])
        try:
            dec_str = decrypted.decode('ascii')
            if dec_str.startswith('c2c{'):
                # Find the end
                end = dec_str.find('}')
                if end > 0:
                    flag = dec_str[:end+1]
                    print(f"  FLAG FOUND at offset 0x{i:x}: {flag}")
        except:
            pass

# Also search for raw "c2c{" in metadata (in case keys are all 0 initially)
print("\n--- Searching metadata for 'c2c{' directly ---")
search = b"c2c{"
idx = 0
while True:
    idx = metadata.find(search, idx)
    if idx == -1:
        break
    context = metadata[idx:idx+100]
    end = context.find(b'}')
    if end > 0:
        flag_candidate = context[:end+1].decode('ascii', errors='replace')
        print(f"  Found at 0x{idx:x}: {flag_candidate}")
    idx += 1

# 2c. Search libil2cpp.so .rodata section
print("\n--- Searching libil2cpp.so for encrypted flag ---")
with open(LIBIL2CPP, 'rb') as f:
    binary = f.read()

# Search for expected encrypted prefix
for i in range(len(binary) - 4):
    if binary[i:i+4] == enc_prefix:
        chunk = binary[i:i+100]
        decrypted = bytes([chunk[j] ^ xor_keys[j % 100] for j in range(len(chunk))])
        try:
            dec_str = decrypted.decode('ascii')
            if dec_str.startswith('c2c{'):
                end = dec_str.find('}')
                if end > 0:
                    flag = dec_str[:end+1]
                    print(f"  FLAG FOUND at offset 0x{i:x}: {flag}")
        except:
            pass

# 2d. Search data.unity3d
print("\n--- Searching data.unity3d for encrypted flag ---")
with open(DATA_UNITY3D, 'rb') as f:
    unity_data = f.read()

for i in range(len(unity_data) - 4):
    if unity_data[i:i+4] == enc_prefix:
        chunk = unity_data[i:i+100]
        decrypted = bytes([chunk[j] ^ xor_keys[j % 100] for j in range(len(chunk))])
        try:
            dec_str = decrypted.decode('ascii')
            if dec_str.startswith('c2c{'):
                end = dec_str.find('}')
                if end > 0:
                    flag = dec_str[:end+1]
                    print(f"  FLAG FOUND at offset 0x{i:x}: {flag}")
        except:
            pass

# 2e. Try with all-zero keys (maybe encrypted text IS the flag, unmodified)
print("\n--- Checking if any string literal IS the flag (no XOR) ---")
for entry in strlits:
    value = entry.get("value", "")
    if value.startswith("c2c{") and value.endswith("}"):
        print(f"  Direct flag: {value}")

# 2f. Search global-metadata.dat for strings near the relevant method addresses
print("\n--- Searching for string refs near Platformer methods ---")
# The string literals in IL2CPP are stored in global-metadata.dat
# Let's look for strings containing common flag format chars
for entry in strlits:
    value = entry.get("value", "")
    if not value:
        continue
    # Check if it could be an encrypted flag (printable ASCII range, reasonable length)
    if 10 <= len(value) <= 80:
        try:
            vbytes = value.encode('latin-1')
            # Try XOR with keys and check if result is readable ASCII  
            decrypted = bytes([vbytes[j] ^ xor_keys[j % 100] for j in range(len(vbytes))])
            dec_str = decrypted.decode('ascii')
            # Check if ALL chars are printable
            if all(32 <= ord(c) < 127 for c in dec_str):
                if 'c2c' in dec_str[:5].lower() or '{' in dec_str[:5]:
                    print(f"  Potential: {value!r} -> {dec_str!r}")
        except:
            pass

print("\n" + "="*80)
print("SUMMARY")
print("="*80)
print(f"Tokens found: {len(token_pairs)}")
print(f"XOR keys array: {xor_keys}")
print(f"XOR keys hex: {bytes(xor_keys).hex()}")

print("\nDONE")
