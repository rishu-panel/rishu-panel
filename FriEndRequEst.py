
import sys
import json
import time
import base64
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV  = b'6oyZDr22E3ychjM%'

# ---------- Endpoint ----------
FrIendU_Rl= "https://client.ind.freefiremobile.com/RequestAddingFriend"
REQ_TYPE = 22  


def encrypt_data(data: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data, AES.block_size))



def _varint(n: int) -> bytes:
    out = []
    while n > 127:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def _tag(field: int, wire_type: int) -> bytes:
    return _varint((field << 3) | wire_type)


def RishuSeNDER(own_uid: int, target_uid: int, req_type: int = REQ_TYPE) -> bytes:
    
    packet = b''
    packet += _tag(1, 0) + _varint(own_uid)     
    packet += _tag(2, 0) + _varint(target_uid)   
    packet += _tag(3, 0) + _varint(req_type)     
    return packet



def decode_jwt(jwt: str) -> dict:
    try:
        payload = jwt.split('.')[1]
        payload += '=' * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception as e:
        raise ValueError(f"Invalid JWT: {e}")


def FriEnd(jwt: str, own_uid: int, target_uid: int) -> dict:
    plain = RishuSeNDER(own_uid, target_uid, REQ_TYPE)
    encrypted = encrypt_data(plain)

    headers = {
        "Host": "client.ind.freefiremobile.com",
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "X-GA-SV": str(int(time.time())),
        "Authorization": f"Bearer {jwt}",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB55",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
    }

    print("\n----- Plaintext protobuf (hex) -----")
    print(plain.hex())
    print("\n----- Encrypted payload (hex) -----")
    print(encrypted.hex())

    try:
        resp = requests.post(
            FrIendU_Rl,
            headers=headers,
            data=encrypted,
            timeout=30,
            verify=False,
        )
        return {
            "status_code": resp.status_code,
            "reason": resp.reason,
            "content": resp.content,
            "hex": resp.content.hex(),
        }
    except Exception as e:
        return {"error": str(e)}


def DeCode_ResPoNse(content: bytes) -> dict:
    try:
        import blackboxprotobuf
        decoded, _ = blackboxprotobuf.decode_message(content)

        def clean(obj):
            if isinstance(obj, bytes):
                try:
                    return obj.decode('utf-8')
                except Exception:
                    return obj.hex()
            if isinstance(obj, dict):
                return {k: clean(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [clean(i) for i in obj]
            return obj

        return clean(decoded)
    except Exception:
        return {"raw_hex": content.hex()}



def main():
    print("\nFrEEFire Friend Request Sender")
    print("=" * 45)

    jwt = input("EnTR Your JwT: ").strip()
    if not jwt:
        print("❌ JWT Required")
        return

    target = input("Enter Target UID: ").strip()
    if not target.isdigit():
        print("❌ Target UID must be a number.")
        return
    target_uid = int(target)

 
    try:
        info = decode_jwt(jwt)
        own_uid = int(info.get("account_id"))
        print(f"👤 Your ACCOnT Id (from JWT): {own_uid}")
        print(f"🆔 NiCkName              : {info.get('nickname', '?')}")
        print(f"🌍 ReGiOn                : {info.get('noti_region', '?')}")
    except Exception as e:
        print(f"❌ Could not extract account_id from JWT: {e}")
        return

    print(f"\n⏳ SeNding reQuest→ UID {target_uid} ...")

    result = FriEnd(jwt, own_uid, target_uid)

    if "error" in result:
        print(f"\n❌ Error: {result['error']}")
        return

    print("\n----- Response -----")
    print(f"✅ HTTP Status : {result['status_code']} {result.get('reason', '')}")
    print(f"📦 Response hex: {result['hex'] or '(empty)'}")

    content = result.get("content", b"")
    if content:
        try:
            decoded = DeCode_ResPoNse(content)
            print("\n📋 Decoded response:")
            print(json.dumps(decoded, indent=2, default=str))
        except Exception as e:
            print(f"⚠️ Could not decode protobuf: {e}")

    print("\n✅ Request complete.")


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()