

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== AES CONFIGURATION ====================
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

def encrypt_api(plain_hex):
    plain = bytes.fromhex(plain_hex)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(plain, AES.block_size)).hex()

def encode_varint(n):
    if n < 0:
        return b''
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

def build_proto(fields):
    def create_field(field_num, value):
        if isinstance(value, dict):
            nested = build_proto(value)
            header = (field_num << 3) | 2
            return encode_varint(header) + encode_varint(len(nested)) + nested
        elif isinstance(value, list):
            return b''.join(create_field(field_num, item) for item in value)
        elif isinstance(value, int):
            header = (field_num << 3) | 0
            return encode_varint(header) + encode_varint(value)
        elif isinstance(value, str):
            header = (field_num << 3) | 2
            encoded = value.encode()
            return encode_varint(header) + encode_varint(len(encoded)) + encoded
        return b''
    result = b''
    for k, v in sorted(fields.items()):
        result += create_field(k, v)
    return result

def build_gallery_request(items):
    items_sublist = []
    for i, item_id in enumerate(items):
        if i % 2 == 0:
            item_block = {1: 2, 4: 2, 5: 2, 6: {6: item_id}}
        else:
            item_block = {1: 9, 2: 9, 4: 2, 6: {6: item_id}}
        items_sublist.append(item_block)
    root = {
        1: 1,
        2: [
            {1: 2, 2: {}},
            {1: 5, 2: {4: 1}},
            {1: 1, 2: items_sublist}
        ]
    }
    return build_proto(root)

def encrypt_request(items):
    plain_bytes = build_gallery_request(items)
    encrypted_hex = encrypt_api(plain_bytes.hex())
    return bytes.fromhex(encrypted_hex)

def send_gallery_request(jwt, items, url="https://client.ind.freefiremobile.com/SetPlayerGalleryShowInfo"):
    encrypted_body = encrypt_request(items)
    headers = {
        "User-Agent": "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Authorization": f"Bearer {jwt}",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB54",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2022.3.47f1"
    }
    resp = requests.post(url, headers=headers, data=encrypted_body, verify=False)
    return resp.status_code, resp.content

def main():
    print("\n🏆 Gallery Showcase Setter (Interactive)")
    print("=" * 50)
    jwt = input("Enter JWT: ").strip()
    if not jwt:
        print("❌ No JWT provided.")
        return

    item_input = input("Enter item IDs (space-separated, e.g., 203000573 909000001): ").strip()
    if not item_input:
        print("❌ No item IDs provided.")
        return

    try:
        items = [int(x) for x in item_input.split()]
    except ValueError:
        print("❌ Invalid item IDs – must be numbers.")
        return

    print(f"\n🚀 Sending {len(items)} item(s) to gallery...")
    status, resp = send_gallery_request(jwt, items)
    print(f"HTTP Status: {status}")
    if status == 200:
        print("✅ Gallery updated successfully!")
    else:
        try:
            print(f"Response: {resp.decode('utf-8')}")
        except:
            print(f"Response hex: {resp.hex()}")

if __name__ == "__main__":
    main()