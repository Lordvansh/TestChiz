from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import aiohttp
import requests
import json
import os
import like_pb2
import uid_generator_pb2

app = Flask(__name__)

# Narayan’s API for token generation
TOKEN_API = "https://narayan-gwt-token-api.vercel.app/token?uid={uid}&password={password}"
ACCOUNTS_FILE = "token_ind.json"  # contains uid + password, NOT tokens


# ---------------- TOKEN GENERATION ---------------- #

def fetch_tokens_from_accounts():
    """Read UID+password from token_ind.json and generate tokens via Narayan API."""
    if not os.path.exists(ACCOUNTS_FILE):
        app.logger.error(f"❌ {ACCOUNTS_FILE} not found.")
        return None

    try:
        with open(ACCOUNTS_FILE, "r") as f:
            accounts = json.load(f)
    except Exception as e:
        app.logger.error(f"❌ Error reading {ACCOUNTS_FILE}: {e}")
        return None

    tokens = []
    for acc in accounts:
        uid = acc.get("uid")
        password = acc.get("password")
        if not uid or not password:
            continue

        try:
            url = TOKEN_API.format(uid=uid, password=password)
            resp = requests.get(url, timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                token = data.get("token")
                if token:
                    tokens.append({"token": token})
                    app.logger.info(f"[{uid}] ✅ Token generated.")
                else:
                    app.logger.error(f"[{uid}] ⚠️ No token in response.")
            else:
                app.logger.error(f"[{uid}] ⚠️ Status {resp.status_code}")
        except Exception as e:
            app.logger.error(f"[{uid}] ❌ Error: {e}")

    return tokens if tokens else None


# ---------------- ENCRYPTION ---------------- #

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"❌ Encryption failed: {e}")
        return None


# ---------------- PROTOBUF HELPERS ---------------- #

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"❌ Protobuf creation failed: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"❌ UID protobuf failed: {e}")
        return None


# ---------------- NETWORK ---------------- #

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 10; ASUS_Z01QD Build/Release)"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    app.logger.error(f"❌ Request failed {response.status}")
                    return {"status": response.status}
                return await response.text()
    except Exception as e:
        app.logger.error(f"❌ Request exception: {e}")
        return None


async def send_multiple_requests(uid, server_name, url, total_requests=5):
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            return None

        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            return None

        tokens = fetch_tokens_from_accounts()
        if not tokens:
            app.logger.error("❌ No tokens generated from accounts.")
            return None

        tasks = []
        for i in range(total_requests):
            token = tokens[i % len(tokens)].get("token")
            if not token:
                continue
            tasks.append(send_request(encrypted_uid, token, url))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        app.logger.error(f"❌ send_multiple_requests failed: {e}")
        return None


# ---------------- ROUTES ---------------- #

@app.route('/like', methods=['GET'])
def like():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name")

    if not uid or not server_name:
        return jsonify({"error": "Missing uid or server_name"}), 400

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(
            send_multiple_requests(uid, server_name, "https://example.com/like", total_requests=3)
        )
        if results is None:
            return jsonify({"error": "Process failed, check logs"}), 500
        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/debug', methods=['GET'])
def debug():
    tokens = fetch_tokens_from_accounts()
    return jsonify({
        "tokens": tokens
    })
