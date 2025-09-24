from flask import Flask, request, jsonify
import asyncio
import random
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError

app = Flask(__name__)

TOKENS_FILE = "tokens.json"   # Pre-generated India tokens

# ---------------- PROXY ---------------- #
PROXY_AUTH = "Quantum-xeqty9ai:PjU3hbsGPEu3iIMT9kpo_country-SG"
PROXY_HOST = "schro.quantumproxies.net:1111"

PROXY_URL = f"http://{PROXY_AUTH}@{PROXY_HOST}"
PROXIES = {"http": PROXY_URL, "https": PROXY_URL}


# ---------------- TOKEN MANAGEMENT ---------------- #

def load_tokens():
    try:
        with open(TOKENS_FILE, "r") as f:
            tokens = json.load(f)
        return tokens
    except Exception as e:
        app.logger.error(f"Error loading {TOKENS_FILE}: {e}")
        return None


# ---------------- ENCRYPTION ---------------- #

def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return binascii.hexlify(encrypted_message).decode('utf-8')


def create_protobuf_message(user_id):
    message = like_pb2.like()
    message.uid = int(user_id)
    message.region = "IND"   # Hardcoded India region
    return message.SerializeToString()


def create_protobuf(uid):
    message = uid_generator_pb2.uid_generator()
    message.saturn_ = int(uid)
    message.garena = 1
    return message.SerializeToString()


def enc(uid):
    return encrypt_message(create_protobuf(uid))


def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(bytes.fromhex(binary))
        return items
    except Exception:
        try:
            return {"raw_response": bytes.fromhex(binary).decode(errors="ignore")}
        except Exception:
            return {"raw_response": binary}


# ---------------- NETWORK ---------------- #

async def send_request(encrypted_uid, token, url, retries=3):
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
    for attempt in range(retries):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, data=edata, headers=headers, proxy=PROXY_URL) as response:
                    if response.status == 200:
                        return await response.text()
                    elif response.status == 503 and attempt < retries - 1:
                        await asyncio.sleep(1)  # retry delay
                    else:
                        return f"HTTP {response.status}"
        except Exception as e:
            if attempt == retries - 1:
                return f"Error: {e}"
            await asyncio.sleep(1)


async def send_multiple_requests(uid, url, total_requests=100):
    protobuf_message = create_protobuf_message(uid)
    encrypted_uid = encrypt_message(protobuf_message)
    tokens = load_tokens()
    if not tokens:
        return None

    results = []
    for i in range(total_requests):
        token = random.choice(tokens)["token"]  # rotate tokens
        result = await send_request(encrypted_uid, token, url)
        results.append(result)
        await asyncio.sleep(0.2)  # throttle delay
    return results


def make_request(encrypt, token, url):
    edata = bytes.fromhex(encrypt)
    headers = {
        'User-Agent': "Dalvik/2.1.0",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
    }
    response = requests.post(url, data=edata, headers=headers, proxies=PROXIES, verify=False)

    try:
        return decode_protobuf(response.content.hex())
    except Exception as e:
        return {"raw_response": response.content.decode(errors="ignore"), "error": str(e)}


# ---------------- ROUTES ---------------- #

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    if not uid:
        return jsonify({"error": "UID is required"}), 400

    try:
        tokens = load_tokens()
        if not tokens:
            return jsonify({"error": "No tokens available"}), 500

        token = random.choice(tokens)['token']  # rotate info token
        encrypted_uid = enc(uid)

        # India endpoints
        info_url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        like_url = "https://clientbp.ggblueshark.com/LikeProfile"

        # Before likes
        before = make_request(encrypted_uid, token, info_url)
        if isinstance(before, dict) and "raw_response" in before:
            return jsonify({"error": "Unexpected response before likes", "details": before["raw_response"]})

        before_like = int(json.loads(MessageToJson(before)).get('AccountInfo', {}).get('Likes', 0))

        # Send likes
        asyncio.run(send_multiple_requests(uid, like_url, total_requests=len(tokens)))

        # After likes
        after = make_request(encrypted_uid, token, info_url)
        if isinstance(after, dict) and "raw_response" in after:
            return jsonify({"error": "Unexpected response after likes", "details": after["raw_response"]})

        data_after = json.loads(MessageToJson(after))
        after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
        player_uid = int(data_after.get('AccountInfo', {}).get('UID', 0))
        player_name = str(data_after.get('AccountInfo', {}).get('PlayerNickname', ''))

        like_given = after_like - before_like
        status = 1 if like_given > 0 else 2

        return jsonify({
            "LikesGivenByAPI": like_given,
            "LikesafterCommand": after_like,
            "LikesbeforeCommand": before_like,
            "PlayerNickname": player_name,
            "UID": player_uid,
            "status": status
        })
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/debug', methods=['GET'])
def debug():
    tokens = load_tokens()
    return jsonify({
        "TokenCount": len(tokens) if tokens else 0,
        "SampleUID": tokens[0]["uid"] if tokens else None,
        "Proxy": PROXY_URL
    })


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
