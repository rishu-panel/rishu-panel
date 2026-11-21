#!/usr/bin/env python3
"""
Free Fire Bio Changer – manual protobuf construction.
Takes JWT and bio text, tries all region endpoints.
"""

import sys
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== CONSTANTS ====================
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
FREEFIRE_VERSION = "OB55"

UPDATE_URLS = [
    "https://client.ind.freefiremobile.com/UpdateSocialBasicInfo"
    ]

HEADERS_TEMPLATE = {
    "Expect": "100-continue",
    "X-Unity-Version": "2018.4.11f1",
    "X-GA": "v1 1",
    "ReleaseVersion": FREEFIRE_VERSION,
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
}

# ==================== PROTOBUF HELPERS ====================
def encode_varint(n: int) -> bytes:
    """Encode an integer as a Protobuf varint."""
    result = []
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            byte |= 0x80
        result.append(byte)
        if not n:
            break
    return bytes(result)

def build_field(field_num: int, value) -> bytes:
    """Build a protobuf field (tag + value)."""
    if isinstance(value, int):
        # Varint field (wire type 0)
        tag = encode_varint((field_num << 3) | 0)
        return tag + encode_varint(value)
    elif isinstance(value, str):
        # String field (wire type 2)
        data = value.encode('utf-8')
        tag = encode_varint((field_num << 3) | 2)
        return tag + encode_varint(len(data)) + data
    elif isinstance(value, bytes):
        # Bytes field (wire type 2)
        tag = encode_varint((field_num << 3) | 2)
        return tag + encode_varint(len(value)) + value
    else:
        raise ValueError(f"Unsupported type: {type(value)}")

def build_bio_payload(bio_text: str) -> bytes:
    """
    Build BioData protobuf manually from captured structure.
    Fields:
        2: int 17
        5: empty message (length 0)
        6: empty message (length 0)
        8: string (bio text)
        9: int 1
        11: empty message (length 0)
        12: empty message (length 0)
    """
    packet = bytearray()

    # field 2: int 17 (tag 16, varint 17)
    packet.extend(build_field(2, 17))

    # field 5: empty message (tag 42, length 0)
    packet.extend(build_field(5, b''))

    # field 6: empty message (tag 50, length 0)
    packet.extend(build_field(6, b''))

    # field 8: string (bio text) (tag 66)
    packet.extend(build_field(8, bio_text))

    # field 9: int 1 (tag 72, varint 1)
    packet.extend(build_field(9, 1))

    # field 11: empty message (tag 90, length 0)
    packet.extend(build_field(11, b''))

    # field 12: empty message (tag 98, length 0)
    packet.extend(build_field(12, b''))

    return bytes(packet)

# ==================== CRYPTO ====================
def encrypt_data(data_bytes: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded = pad(data_bytes, AES.block_size)
    return cipher.encrypt(padded)

# ==================== MAIN ====================
def main():
    print("\n" + "="*50)
    print("  FREE FIRE BIO CHANGER")
    print("="*50 + "\n")

    jwt = input("Enter your JWT: ").strip()
    if not jwt:
        print("❌ No JWT provided.")
        return

    bio = input("Enter new bio text: ").strip()
    if not bio:
        print("❌ Bio cannot be empty.")
        return

    # Build and encrypt payload
    try:
        plain = build_bio_payload(bio)
        encrypted = encrypt_data(plain)
    except Exception as e:
        print(f"❌ Failed to build payload: {e}")
        return

    headers = HEADERS_TEMPLATE.copy()
    headers["Authorization"] = f"Bearer {jwt}"

    print("📤 Sending bio update...")
    success = False
    for url in UPDATE_URLS:
        try:
            resp = requests.post(url, headers=headers, data=encrypted, timeout=15, verify=False)
            if resp.status_code == 200:
                print(f"✅ Bio updated successfully using {url}!")
                print(f"   New bio: {bio}")
                success = True
                break
            else:
                print(f"   ⚠️ {url} returned HTTP {resp.status_code}")
        except Exception as e:
            print(f"   ❌ {url} error: {e}")

    if not success:
        print("❌ All endpoints failed. Bio not updated.")

if __name__ == "__main__":
    main()