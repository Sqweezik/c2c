"""Extract files from PyInstaller binary manually"""
import struct
import sys
import os
import zlib

CHALL = r"C:\Users\sq\Desktop\c2c\not-malicious-extension\dist\dist\chall"
OUTDIR = r"C:\Users\sq\Desktop\c2c\not-malicious-extension\extracted"

os.makedirs(OUTDIR, exist_ok=True)

with open(CHALL, "rb") as f:
    data = f.read()

print(f"Binary size: {len(data)}")

# PyInstaller creates a CArchive at the end of the binary
# The cookie (MAGIC) is "MEI\014\013\012\013\016" at the end
PYINST_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"

# Find the magic
pos = data.rfind(PYINST_MAGIC)
if pos == -1:
    print("PyInstaller magic not found!")
    sys.exit(1)

print(f"Found PyInstaller magic at offset {pos} (0x{pos:x})")

# Cookie structure (after magic):
# 4 bytes: package length
# 4 bytes: TOC offset (relative to package start)
# 4 bytes: TOC length
# 4 bytes: python version (e.g., 311 for 3.11)
# 64 bytes: python dll name
cookie_offset = pos
cookie_data = data[cookie_offset:]

# PyInstaller 6.x cookie format:
# 8 bytes: magic
# 4 bytes: len of package
# 4 bytes: TOC position (from start of package)
# 4 bytes: TOC length  
# 4 bytes: Python version
# 64 bytes: Python library name

magic = cookie_data[:8]
pkg_len = struct.unpack(">I", cookie_data[8:12])[0]
toc_offset = struct.unpack(">I", cookie_data[12:16])[0]
toc_len = struct.unpack(">I", cookie_data[16:20])[0]
pyver = struct.unpack(">I", cookie_data[20:24])[0]
pylib = cookie_data[24:88].split(b'\x00')[0].decode('utf-8', errors='replace')

print(f"Package length: {pkg_len}")
print(f"TOC offset: {toc_offset}")
print(f"TOC length: {toc_len}")
print(f"Python version: {pyver}")
print(f"Python lib: {pylib}")

# Package starts at: cookie_offset + 24 + 64 - pkg_len? 
# Actually: package starts at overlay_start = len(data) - pkg_len
# But cookie is at the END of the package
# overlay_start = file_size - pkg_len? No...
# The cookie is at the end of the file.
# pkg_len is the total size of the archive
# overlay_start = pos + 8 + 4 + 4 + 4 + 4 + 64 - pkg_len
# Actually: overlay_end = pos + 8 + 4 + 4 + 4 + 4 + 64 = pos + 88
# overlay_start = overlay_end - pkg_len

overlay_end = pos + 88
overlay_start = overlay_end - pkg_len
print(f"Overlay start: {overlay_start}, end: {overlay_end}")

# TOC starts at overlay_start + toc_offset
toc_start = overlay_start + toc_offset
toc_end = toc_start + toc_len

print(f"TOC: {toc_start}..{toc_end}")

# Parse TOC entries
# Each TOC entry:
# 4 bytes: entry length (including these 4 bytes and the name)
# 4 bytes: offset (relative to overlay_start)
# 4 bytes: compressed data length
# 4 bytes: uncompressed data length
# 1 byte: compression flag (0=not compressed, 1=compressed)
# 1 byte: type flag
# name: null-terminated string

offset = toc_start
entries = []
while offset < toc_end:
    entry_len = struct.unpack(">I", data[offset:offset+4])[0]
    if entry_len < 18:
        break
    d_offset = struct.unpack(">I", data[offset+4:offset+8])[0]
    c_len = struct.unpack(">I", data[offset+8:offset+12])[0]
    u_len = struct.unpack(">I", data[offset+12:offset+16])[0]
    cflag = data[offset+16]
    typflag = chr(data[offset+17])
    name = data[offset+18:offset+entry_len].split(b'\x00')[0].decode('utf-8', errors='replace')
    
    entries.append({
        'name': name,
        'offset': d_offset,
        'clen': c_len,
        'ulen': u_len,
        'compressed': cflag,
        'type': typflag
    })
    
    offset += entry_len

print(f"\nFound {len(entries)} TOC entries:")
for e in entries:
    print(f"  [{e['type']}] {e['name']} (compressed={e['compressed']}, clen={e['clen']}, ulen={e['ulen']})")

# Extract all entries
for e in entries:
    abs_offset = overlay_start + e['offset']
    raw = data[abs_offset:abs_offset + e['clen']]
    
    if e['compressed']:
        try:
            content = zlib.decompress(raw)
        except:
            content = raw
    else:
        content = raw
    
    # Create subdirectories if needed
    outpath = os.path.join(OUTDIR, e['name'].replace('/', os.sep))
    os.makedirs(os.path.dirname(outpath) if os.path.dirname(outpath) else OUTDIR, exist_ok=True)
    
    with open(outpath, 'wb') as f:
        f.write(content)
    
    if e['name'] in ('chall', 'c2cext.cpython-311-x86_64-linux-gnu.so'):
        print(f"  ** Extracted key file: {e['name']} ({len(content)} bytes)")
