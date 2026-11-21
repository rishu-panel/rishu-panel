#!/usr/bin/env python3
# AYUSH PANEL 👑

import sys
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== CONFIG ====================
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

# Endpoints for different regions
REGION_BASES = {
    "IND": "https://client.ind.freefiremobile.com",
 
}

def encrypt_data(data: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data, AES.block_size))

def encode_varint(n: int) -> bytes:
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

# ==================== PAYLOAD BUILDERS ====================
def build_guild_join_payload(guild_id: int) -> bytes:
    body = encode_varint(8) + encode_varint(guild_id)   # field1 = guild_id
    body += encode_varint(16) + encode_varint(1)        # field2 = 1
    return body

def build_guild_leave_payload(guild_id: int) -> bytes:
    return encode_varint(8) + encode_varint(guild_id)

def build_friend_request_payload(target_uid: int) -> bytes:
    body = encode_varint(8) + encode_varint(target_uid)   # field1 = target
    body += encode_varint(16) + encode_varint(1)          # field2 = 1
    body += encode_varint(24) + encode_varint(26)         # field3 = 26
    return body

def build_remove_friend_payload(target_uid: int) -> bytes:
    body = encode_varint(8) + encode_varint(target_uid)
    body += encode_varint(16) + encode_varint(1)
    return body

# ==================== ACTION FUNCTIONS ====================
def try_endpoint(base_url, endpoint, jwt, payload):
    url = f"{base_url}{endpoint}"
    headers = {
        "User-Agent": "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Authorization": f"Bearer {jwt}",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB55",
        "Content-Type": "application/octet-stream",
        "X-Unity-Version": "2022.3.47f1"
    }
    encrypted = encrypt_data(payload)
    try:
        resp = requests.post(url, headers=headers, data=encrypted, verify=False, timeout=15)
        return resp.status_code, resp.content
    except Exception as e:
        return None, str(e)

def guild_join(jwt: str, guild_id: int) -> tuple:
    payload = build_guild_join_payload(guild_id)
    for region, base in REGION_BASES.items():
        status, resp = try_endpoint(base, "/RequestJoinClan", jwt, payload)
        if status == 200:
            return status, resp
        elif status is not None and status != 200:
            continue
        else:
            print(f"⚠️ {region} error: {resp}")
    return 500, b"All endpoints failed"

def guild_leave(jwt: str, guild_id: int) -> tuple:
    payload = build_guild_leave_payload(guild_id)
    for region, base in REGION_BASES.items():
        status, resp = try_endpoint(base, "/QuitClan", jwt, payload)
        if status == 200:
            return status, resp
    return 500, b"All endpoints failed"

def send_friend_request(jwt: str, target_uid: int) -> tuple:
    payload = build_friend_request_payload(target_uid)
    for region, base in REGION_BASES.items():
        status, resp = try_endpoint(base, "/RequestAddingFriend", jwt, payload)
        if status == 200:
            return status, resp
    return 500, b"All endpoints failed"

def remove_friend(jwt: str, target_uid: int) -> tuple:
    payload = build_remove_friend_payload(target_uid)
    for region, base in REGION_BASES.items():
        status, resp = try_endpoint(base, "/RemoveFriend", jwt, payload)
        if status == 200:
            return status, resp
    return 500, b"All endpoints failed"

# ==================== MENU ====================
def print_menu():
    print("\n" + "=" * 50)
    print("   Free Fire Action Tool")
    print("=" * 50)
    print("1. GUILD JOIN")
    print("2. GUILD LEAVE")
    print("3. SEND FRIEND REQUEST")
    print("4. REMOVE FRIEND")
    print("0. EXIT")
    print("AYUSH PANEL 👑")
    print("=" * 50)

def main():
    jwt = input("Enter your JWT: ").strip()
    if not jwt:
        print("❌ No JWT provided.")
        return

    while True:
        print_menu()
        choice = input("Select option (0-4): ").strip()
        if choice == "0":
            print("Bye.")
            break
        elif choice == "1":
            try:
                gid = int(input("Enter Guild ID to join: ").strip())
                status, resp = guild_join(jwt, gid)
                print(f"HTTP Status: {status}")
                if status == 200:
                    print("✅ Guild join request sent.")
                else:
                    print(f"❌ Failed: {resp[:200].decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"Error: {e}")
        elif choice == "2":
            try:
                gid = int(input("Enter Guild ID to leave: ").strip())
                status, resp = guild_leave(jwt, gid)
                print(f"HTTP Status: {status}")
                if status == 200:
                    print("✅ Guild leave request sent.")
                else:
                    print(f"❌ Failed: {resp[:200].decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"Error: {e}")
        elif choice == "3":
            try:
                target_uid = int(input("Enter target player UID: ").strip())
                status, resp = send_friend_request(jwt, target_uid)
                print(f"HTTP Status: {status}")
                if status == 200:
                    print("✅ Friend request sent.")
                else:
                    print(f"❌ Failed: {resp[:200].decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"Error: {e}")
        elif choice == "4":
            try:
                uid = int(input("Enter friend UID to remove: ").strip())
                status, resp = remove_friend(jwt, uid)
                print(f"HTTP Status: {status}")
                if status == 200:
                    print("✅ Friend removed.")
                else:
                    print(f"❌ Failed: {resp[:200].decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"Error: {e}")
        else:
            print("Invalid choice. Please enter 0-4.")
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
