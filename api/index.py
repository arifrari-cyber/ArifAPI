from fastapi import FastAPI, HTTPException, Query
import requests
import json
import base64
import os
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import urllib3

# Disable warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI()

# Configuration from ArifLogin.py
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

# Crypto & Protobuf Helpers
def EnC_Vr(N):
    if N < 0: return b''
    H = []
    while True:
        BesTo = N & 0x7F
        N >>= 7
        if N: BesTo |= 0x80
        H.append(BesTo)
        if not N: break
    return bytes(H)

def CrEaTe_VarianT(field_number, value):
    field_header = (field_number << 3) | 0
    return EnC_Vr(field_header) + EnC_Vr(value)

def CrEaTe_LenGTh(field_number, value):
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return EnC_Vr(field_header) + EnC_Vr(len(encoded_value)) + encoded_value

def CrEaTe_ProTo(fields):
    packet = bytearray()    
    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = CrEaTe_ProTo(value)
            packet.extend(CrEaTe_LenGTh(field, nested_packet))
        elif isinstance(value, int):
            packet.extend(CrEaTe_VarianT(field, value))           
        elif isinstance(value, str) or isinstance(value, bytes):
            packet.extend(CrEaTe_LenGTh(field, value))           
    return packet

def encrypt_api(plain_text_hex):
    plain_text = bytes.fromhex(plain_text_hex)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def decrypt_api(encrypted_data):
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        decrypted_padded = cipher.decrypt(encrypted_data)
        return unpad(decrypted_padded, AES.block_size)
    except:
        return encrypted_data

def parse_major_login_response(content):
    try:
        decrypted = decrypt_api(content)
        text = decrypted.decode('utf-8', errors='ignore')
        jwt_start = text.find("eyJ")
        if jwt_start != -1:
            jwt_token = text[jwt_start:]
            parts = jwt_token.split('.')
            if len(parts) >= 3:
                 signature = parts[2]
                 valid_sig = ""
                 for char in signature:
                     if char in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_":
                         valid_sig += char
                     else:
                         break
                 return f"{parts[0]}.{parts[1]}.{valid_sig}"
    except:
        pass
    return None

def guest_token(uid, password, session):
    app_id = 100067
    url = f"https://{app_id}.connect.garena.com/api/v2/oauth/guest/token:grant"
    payload = {
        "client_id": app_id, 
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_type": 2, 
        "password": str(password), 
        "response_type": "token", 
        "uid": int(uid)
    }
    headers = {"Content-Type": "application/json"}
    try:
        resp = session.post(url, headers=headers, json=payload, timeout=12, verify=False).json()
        if resp.get('code') == 0 and 'data' in resp:
            return resp['data']['access_token'], resp['data']['open_id']
    except Exception as e:
        print(f"Guest token error: {e}")
    return None, None

def major_login(access_token, open_id, session):
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        "Accept-Encoding": "gzip",
        "Authorization": "Bearer",
        "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "Expect": "100-continue",
        "Host": "loginbp.ggblueshark.com",
        "ReleaseVersion": "OB53",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
        "X-GA": "v1 1",
        "X-Unity-Version": "2018.4.11f1"
    }
    
    payload = {
        3: str(datetime.now())[:-7], 
        4: "free fire",               
        5: 1,                         
        7: "1.123.1",                 
        8: "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)", 
        9: "Handheld",                
        10: "Verizon",                
        11: "WIFI",                   
        12: 1920,                     
        13: 1080,                     
        14: "280",                    
        15: "ARM64 FP ASIMD AES VMH | 2865 | 4", 
        16: 3003,                     
        17: "Adreno (TM) 640",        
        18: "OpenGL ES 3.1 v1.46",    
        19: "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57", 
        20: "223.191.51.89",           
        21: "en",                     
        22: str(open_id),             
        23: "4",                      
        24: "Handheld",               
        25: {                         
            6: 55, 
            8: 81
        },
        29: str(access_token),        
        30: 1,                        
        41: "Verizon",                
        42: "WIFI",                   
        57: "7428b253defc164018c604a1ebbfebdf", 
        60: 36235,                    
        61: 31335,                    
        62: 2519,                     
        63: 703,                      
        64: 25010,                    
        65: 26628,                    
        66: 32992,                    
        67: 36235,                    
        73: 3,                        
        74: "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64", 
        76: 1,                        
        77: "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk", 
        78: 3,                        
        79: 2,                        
        81: "64",                     
        83: "2019118695",             
        86: "OpenGLES2",              
        87: 16383,                    
        88: 4,                        
        89: base64.b64decode("FwQVTgUPX1UaUllDDwcWCRBpWA0FUgsvA1snWlBaO1kFYg=="), 
        92: 13564,                    
        93: "android",                
        94: "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY=", 
        95: 110009,                   
        97: 1,                        
        98: 1,                        
        99: "4",                      
        100: "4"                      
    }
    
    payload_bytes = CrEaTe_ProTo(payload)
    encrypted_payload = encrypt_api(payload_bytes.hex())
    final_payload = bytes.fromhex(encrypted_payload)
    
    try:
        resp = session.post(url, headers=headers, data=final_payload, timeout=15, verify=False)
        return resp.content
    except Exception as e:
        print(f"Major login error: {e}")
        return None

# Persistence Logic (Local only, Vercel /tmp)
ACCOUNTS_FILE = "accounts.json"

@app.get("/")
def home():
    return {"status": "Arif API is running", "endpoint": "/get_token", "params": ["uid", "password"]}

@app.get("/{params}")
def get_token_shorthand(params: str):
    # Parse format like u=UID&p=PASS
    uid = None
    password = None
    
    parts = params.split("&")
    for part in parts:
        if part.startswith("u="):
            uid = part.split("u=")[1]
        elif part.startswith("p="):
            password = part.split("p=")[1]
            
    if not uid or not password:
        # Fallback to old | format just in case
        if "|" in params:
            uid, password = params.split("|", 1)
        else:
            raise HTTPException(status_code=400, detail="Invalid format. Use u=UID&p=PASS")
    
    # Generate Token
    session = requests.Session()
    acc_token, open_id = guest_token(uid, password, session)
    
    if not acc_token or not open_id:
        save_account(uid, password, status="failed")
        raise HTTPException(status_code=400, detail="Guest login failed.")

    login_resp = major_login(acc_token, open_id, session)
    if not login_resp:
        save_account(uid, password, status="major_login_failed")
        raise HTTPException(status_code=400, detail="Major Login failed.")

    jwt = parse_major_login_response(login_resp)
    if not jwt:
        save_account(uid, password, status="jwt_failed")
        raise HTTPException(status_code=400, detail="JWT extraction failed.")

    # Save successful attempt
    save_account(uid, password, status="success")

    # Response with only token and uid
    return {
        "uid": uid,
        "token": jwt
    }

def save_account(uid, password, status="unknown"):
    try:
        accounts_data = {"accounts": []}
        if os.path.exists(ACCOUNTS_FILE):
            with open(ACCOUNTS_FILE, "r") as f:
                accounts_data = json.load(f)
        
        # Update or add
        updated = False
        for acc in accounts_data["accounts"]:
            if acc["uid"] == uid:
                acc["password"] = password
                acc["status"] = status
                acc["updated_at"] = str(datetime.now())
                updated = True
                break
        
        if not updated:
            accounts_data["accounts"].append({
                "uid": uid, 
                "password": password, 
                "status": status,
                "added_at": str(datetime.now())
            })
            
        with open(ACCOUNTS_FILE, "w") as f:
            json.dump(accounts_data, f, indent=4)
    except Exception as e:
        print(f"Persistence error: {e}")

@app.get("/get_all_tokens")
def get_all_tokens():
    if not os.path.exists(ACCOUNTS_FILE):
        return {"status": "error", "message": "No accounts stored."}
    
    with open(ACCOUNTS_FILE, "r") as f:
        accounts_data = json.load(f)
    
    results = []
    session = requests.Session()
    for acc in accounts_data.get("accounts", []):
        uid = acc["uid"]
        password = acc["password"]
        
        try:
            acc_token, open_id = guest_token(uid, password, session)
            if acc_token and open_id:
                login_resp = major_login(acc_token, open_id, session)
                jwt = parse_major_login_response(login_resp)
                results.append({
                    "uid": uid,
                    "token": jwt or "Failed to extract JWT",
                    "status": "success" if jwt else "failed"
                })
            else:
                results.append({"uid": uid, "status": "failed", "detail": "Guest login failed"})
        except Exception as e:
            results.append({"uid": uid, "status": "error", "detail": str(e)})
            
    return {"status": "complete", "results": results}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
