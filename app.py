from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import os
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError

app = Flask(__name__)

TOKEN_API = "https://ff-token-generator.vercel.app/token?uid={uid}&password={password}"

# ---------------- TOKEN HANDLING ---------------- #

def generate_tokens_from_uid_password(ind_accounts_file="ind_ind.json", token_file="token_ind.json"):
    try:
        if not os.path.exists(ind_accounts_file):
            app.logger.error(f"Accounts file {ind_accounts_file} not found.")
            return None

        with open(ind_accounts_file, "r") as f:
            accounts = json.load(f)

        tokens = []
        for acc in accounts:
            uid = acc.get("uid")
            password = acc.get("password")
            if not uid or not password:
                continue

            try:
                url = TOKEN_API.format(uid=uid, password=password)
                resp = requests.get(url, timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    token = data.get("token")
                    if token:
                        tokens.append({"token": token})
                        app.logger.info(f"[{uid}] token generated successfully.")
                    else:
                        app.logger.error(f"[{uid}] no token returned.")
                else:
                    app.logger.error(f"[{uid}] status code {resp.status_code}")
            except Exception as e:
                app.logger.error(f"[{uid}] error generating token: {e}")

        if tokens:
            with open(token_file, "w") as f:
                json.dump(tokens, f, indent=4)
            return tokens
        else:
            return None

    except Exception as e:
        app.logger.error(f"Error in generate_tokens_from_uid_password: {e}")
        return None


def load_tokens(server_name):
    try:
        if server_name == "ME":
            token_file = "token_ind.json"
            if not os.path.exists(token_file):
                return generate_tokens_from_uid_password()

            with open(token_file, "r") as f:
                tokens = json.load(f)

            if not tokens or "token" not in tokens[0]:
                return generate_tokens_from_uid_password()

            return tokens

        elif server_name in {"BR", "US", "SAC", "NA"}:
            with open("token_br.json", "r") as f:
                return json.load(f)
        else:
            with open("token_bd.json", "r") as f:
                return json.load(f)

    except Exception as e:
        app.logger.error(f"Error loading tokens for server {server_name}: {e}")
        return None

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
        app.logger.error(f"Error encrypting message: {e}")
        return None

# ---------------- PROTOBUF HELPERS ---------------- #

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

# ---------------- NETWORK ---------------- #

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 10; ASUS_Z01QD Build/Release)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2019.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB48"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    app.logger.error(f"Request failed with status code: {response.status}")
                    return response.status
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return None


async def send_multiple_requests(uid, server_name, url, total_requests=100):
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            return None
        tokens = load_tokens(server_name)
        if tokens is None:
            return None

        tasks = []
        for i in range(total_requests):
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_request(encrypted_uid, token, url))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return None

# ---------------- ROUTE ---------------- #

@app.route('/like', methods=['GET'])
def like():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name")
    key = request.args.get("key")

    if not uid or not server_name:
        return jsonify({"error": "Missing uid or server_name"}), 400

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(send_multiple_requests(uid, server_name, "https://example.com/like", total_requests=10))
        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
