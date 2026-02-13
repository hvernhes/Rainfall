#!/usr/bin/env python
import sys

def generate_pattern(length):
    pattern = ""
    for i in range(length // 3):
        pattern += chr(65 + (i // 100)) + chr(97 + ((i // 10) % 10)) + chr(48 + (i % 10))
    return pattern[:length]

def find_offset(value):
    if isinstance(value, str):
        if value.startswith("0x"):
            value = int(value, 16)
        else:
            value = int(value, 16)
    
    # Convertir en little-endian bytes
    pattern_bytes = ""
    for i in range(4):
        pattern_bytes += chr((value >> (i * 8)) & 0xFF)
    
    # Générer un grand pattern et chercher
    pattern = generate_pattern(1000)
    offset = pattern.find(pattern_bytes)
    
    if offset != -1:
        return offset
    return -1

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Generate: python pattern.py <length>")
        print("  Find:     python pattern.py 0x37634136")
        sys.exit(1)
    
    arg = sys.argv[1]
    
    if arg.startswith("0x"):
        # Find offset
        offset = find_offset(arg)
        if offset != -1:
            print(f"[+] Offset: {offset}")
        else:
            print("[-] Pattern not found")
    else:
        # Generate pattern
        length = int(arg)
        print(generate_pattern(length))