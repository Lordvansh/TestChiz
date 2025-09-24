from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import jwt
import like_pb2
import like_count_pb2
import uid_generator_pb2

app = Flask(__name__)

TOKENS_FILE = "tokens.json"   # pre-generated tokens file


# ---------------- TOKEN MANAGEMENT ---------------- #

def load_tokens():
    try:
        with open(TOKENS_FILE, "r") as f:
            tokens = json.load(f)
        return tokens
    except Exception as e:
        app.logger.error(f"❌ Error reading {TOKENS_FILE}: {e}")
        return None


def get_region_from_token(token: str) -> str:
    """Decode JWT and return region from claims."""
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        # region can be in noti_region or lock_region
        region = payload.get("noti_region") or payload.get("lock_region")
        if not region:
            return "ME"  # fallback default
        return region.upper()
    except Exception:
        return "ME"  # fallback if token decoding fails


# ---------------- ENCRYPTION ---------------- #

def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return binascii.hexlify(encrypted_message).decode('utf-8')


# ---------------- PROTOBUF HELPERS ---------------- #

def create_protobuf_message(user_id, region):
    message = like_pb2.like()
    message.uid = int(user_id)
    message.region = region
    return message.SerializeToString()

def create_protobuf(uid):
    message = uid_generator_pb2.uid_generator()
    message.saturn_ = int(uid)
    message.garena = 1
    return message.SerializeToString()

def enc(uid):
    return encrypt_message(create_protobuf(uid))


def decode_protobuf(binary):
    items = like_count_pb2.Info()
    items.ParseFromString(bytes.fromhex(binary))
    return items


# ---------------- NETWORK ---------------- #

async def send_request(encrypted_uid, token, url):
    edata = bytes.fromhex(encrypted_uid)
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 10; ASUS_Z01QD Build/Release)",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'X-Unity-Version': "2019.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB48"
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=edata, headers=headers) as response:
            return await response.text() if response.status == 200 else f"HTTP {response.status}"


async def send_multiple_requests(uid, tokens, url, total_requests=50):
    encrypted_uid = encrypt_message(create_protobuf_message(uid, "IND"))  # region not critical for like
    tasks = []
    for i in range(total_requests):
        token = tokens[i % len(tokens)]["token"]
        tasks.append(send_request(encrypted_uid, token, url))
    return await asyncio.gather(*tasks, return_exceptions=True)


def make_request(encrypt, url, token):
    edata = bytes.fromhex(encrypt)
    headers = {
        'User-Agent': "Dalvik/2.1.0",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
    }
    response = requests.post(url, data=edata, headers=headers, verify=False)

    try:
        return decode_protobuf(response.content.hex())
    except Exception:
        return {"raw_response": response.content.decode(errors="ignore")}


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

        # Pick first token → detect region
        sample_token = tokens[0]['token']
        region = get_region_from_token(sample_token)

        # Map region → endpoint
        info_url_map = {
            "IND": "https://clientbp.ggblueshark.com/GetPlayerPersonalShow",
            "ME": "https://clientbp.ggblueshark.com/GetPlayerPersonalShow",
            "BR": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
            "US": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
            "SAC": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
            "NA": "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        }
        like_url_map = {
            "IND": "https://clientbp.ggblueshark.com/LikeProfile",
            "ME": "https://clientbp.ggblueshark.com/LikeProfile",
            "BR": "https://client.us.freefiremobile.com/LikeProfile",
            "US": "https://client.us.freefiremobile.com/LikeProfile",
            "SAC": "https://client.us.freefiremobile.com/LikeProfile",
            "NA": "https://client.us.freefiremobile.com/LikeProfile"
        }

        info_url = info_url_map.get(region, info_url_map["ME"])
        like_url = like_url_map.get(region, like_url_map["ME"])

        token = tokens[0]['token']
        encrypted_uid = enc(uid)

        # Before likes
        before = make_request(encrypted_uid, info_url, token)
        if isinstance(before, dict) and "raw_response" in before:
            return jsonify({"error": "Unexpected response before likes", "details": before["raw_response"]})

        before_like = int(json.loads(MessageToJson(before)).get('AccountInfo', {}).get('Likes', 0))

        # Send likes
        asyncio.run(send_multiple_requests(uid, tokens, like_url, total_requests=len(tokens)))

        # After likes
        after = make_request(encrypted_uid, info_url, token)
        if isinstance(after, dict) and "raw_response" in after:
            return jsonify({"error": "Unexpected response after likes", "details": after["raw_response"]})

        data_after = json.loads(MessageToJson(after))
        after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
        player_uid = int(data_after.get('AccountInfo', {}).get('UID', 0))
        player_name = str(data_after.get('AccountInfo', {}).get('PlayerNickname', ''))

        like_given = after_like - before_like
        status = 1 if like_given > 0 else 2

        return jsonify({
            "RegionDetected": region,
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
    if not tokens:
        return jsonify({"error": "No tokens loaded"})
    first_token = tokens[0]['token']
    region = get_region_from_token(first_token)
    return jsonify({
        "RegionDetected": region,
        "SampleTokenUID": tokens[0].get("uid"),
        "TokenCount": len(tokens)
    })


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
