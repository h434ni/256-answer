#!/usr/bin/env python3
import sys
import base64
import lzma
import struct

MAGIC = b"UNCLEJACKIE"

def generate_seq2(param: bytes, length: int) -> bytes:
    start_byte = (param[-1] - 1) % 256
    step = -1
    return bytes((start_byte + i * step) % 256 for i in range(length))

def generate_ca30(row0: bytes, total_len: int) -> bytes:
    out = bytearray(row0)
    steps = total_len // 64
    x = int.from_bytes(row0, "big")
    MASK = (1 << 512) - 1
    for _ in range(steps - 1):
        left = ((x << 1) | (x >> 511)) & MASK
        right = ((x >> 1) | (x << 511)) & MASK
        x = left ^ (x | right)
        out.extend(x.to_bytes(64, "big"))
    return bytes(out)

def generate_a181(row0: bytes, total_len: int) -> bytes:
    out = bytearray(row0)
    steps = total_len // 32
    x = int.from_bytes(row0, "big")
    MASK = (1 << 256) - 1
    for _ in range(steps - 1):
        L = ((x << 1) | (x >> 255)) & MASK
        R = ((x >> 1) | (x << 255)) & MASK
        x = ((R & L) | ((~R) & ~(L & x))) & MASK
        out.extend(x.to_bytes(32, "big"))
    return bytes(out)

def compress_file(input_path: str, output_path: str):
    with open(input_path, "rb") as f:
        raw_b64 = f.read()

    data = base64.b64decode(raw_b64)
    assert data[:11] == MAGIC, "Invalid UNCLEJACKIE signature"

    header_80 = data[:80]
    offset = 80
    chunks = []

    while offset + 14 <= len(data):
        length = int.from_bytes(data[offset:offset+4], "big")
        tag = data[offset+4:offset+8]
        param = data[offset+8:offset+14]
        payload = data[offset+14:offset+14+length]
        chunks.append((tag, param, payload))
        offset += 14 + length

    archive = bytearray()
    archive.extend(header_80)
    archive.extend(struct.pack(">H", len(chunks)))

    for tag, param, payload in chunks:
        tag_str = tag.decode(errors="replace").strip()
        
        # Test procedural generators
        if tag_str == "SEQ2" and generate_seq2(param, len(payload)) == payload:
            archive.append(0x00)
            archive.extend(tag)
            archive.extend(param)
            archive.extend(struct.pack(">I", len(payload)))
        elif tag_str == "CA30" and generate_ca30(payload[:64], len(payload)) == payload:
            archive.append(0x02) # Mode 2: CA30 (stores 64-byte row0)
            archive.extend(tag)
            archive.extend(param)
            archive.extend(struct.pack(">I", len(payload)))
            archive.extend(payload[:64])
        elif tag_str == "A181" and generate_a181(payload[:32], len(payload)) == payload:
            archive.append(0x03) # Mode 3: A181 (stores 32-byte row0)
            archive.extend(tag)
            archive.extend(param)
            archive.extend(struct.pack(">I", len(payload)))
            archive.extend(payload[:32])
        else:
            # Mode 1: Fallback LZMA
            comp = lzma.compress(payload, preset=6)
            archive.append(0x01)
            archive.extend(tag)
            archive.extend(param)
            archive.extend(struct.pack(">I", len(payload)))
            archive.extend(struct.pack(">I", len(comp)))
            archive.extend(comp)

    with open(output_path, "wb") as f:
        f.write(archive)

def decompress_file(input_path: str, output_path: str):
    with open(input_path, "rb") as f:
        archive = f.read()

    header_80 = archive[:80]
    num_chunks = struct.unpack(">H", archive[80:82])[0]
    offset = 82

    reconstructed = bytearray(header_80)

    for _ in range(num_chunks):
        mode = archive[offset]
        tag = archive[offset+1:offset+5]
        param = archive[offset+5:offset+11]
        orig_length = struct.unpack(">I", archive[offset+11:offset+15])[0]

        if mode == 0x00:
            payload = generate_seq2(param, orig_length)
            offset += 15
        elif mode == 0x02:
            row0 = archive[offset+15:offset+15+64]
            payload = generate_ca30(row0, orig_length)
            offset += 15 + 64
        elif mode == 0x03:
            row0 = archive[offset+15:offset+15+32]
            payload = generate_a181(row0, orig_length)
            offset += 15 + 32
        elif mode == 0x01:
            comp_length = struct.unpack(">I", archive[offset+15:offset+19])[0]
            comp_data = archive[offset+19:offset+19+comp_length]
            payload = lzma.decompress(comp_data)
            offset += 19 + comp_length
        else:
            raise ValueError(f"Unknown mode: {mode}")

        reconstructed.extend(struct.pack(">I", orig_length))
        reconstructed.extend(tag)
        reconstructed.extend(param)
        reconstructed.extend(payload)

    restored_b64 = base64.b64encode(reconstructed)
    with open(output_path, "wb") as f:
        f.write(restored_b64)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        sys.exit(1)
    action, src, dst = sys.argv[1], sys.argv[2], sys.argv[3]
    if action == "--compress":
        compress_file(src, dst)
    elif action == "--decompress":
        decompress_file(src, dst)
