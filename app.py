from flask import Flask, request, jsonify
import asyncio
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

app = Flask(__name__)

# ---------------- CONFIG ---------------- #
TOKENS_FILE = "tokens.json"   # pre-generated tokens file


# ---------------- TOKEN MANAGEMENT ---------------- #

def load_tokens():
    """Load tokens directly from tokens.json."""
    try:
        with open(TOKENS_FILE, "r") as f:
            tokens = json.load(f)
        return tokens
    except Exception as e:
        app.logger.error(f"❌ Error reading {TOKENS_FILE}: {e}")
        return None


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
            return await response.text() if response.status == 200 else None


async def send_multiple_requests(uid, server_name, url, total_requests=50):
    encrypted_uid = encrypt_message(create_protobuf_message(uid, server_name))
    tokens = load_tokens()
    if not tokens:
        return None

    tasks = []
    for i in range(total_requests):
        token = tokens[i % len(tokens)]["token"]
        tasks.append(send_request(encrypted_uid, token, url))
    return await asyncio.gather(*tasks, return_exceptions=True)


def make_request(encrypt, server_name, token):
    url_map = {
        "ME": "https://clientbp.ggblueshark.com/GetPlayerPersonalShow",
        "BR": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "US": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "SAC": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "NA": "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    }
    edata = bytes.fromhex(encrypt)
    headers = {
        'User-Agent': "Dalvik/2.1.0",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
    }
    response = requests.post(url_map.get(server_name, url_map["ME"]), data=edata, headers=headers, verify=False)
    return decode_protobuf(response.content.hex())


# ---------------- ROUTES ---------------- #

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    try:
        tokens = load_tokens()
        if not tokens:
            return jsonify({"error": "No tokens available"}), 500

        token = tokens[0]['token']
        encrypted_uid = enc(uid)

        # Before likes
        before = make_request(encrypted_uid, server_name, token)
        before_like = int(json.loads(MessageToJson(before)).get('AccountInfo', {}).get('Likes', 0))

        url_map = {
            "ME": "https://clientbp.ggblueshark.com/LikeProfile",
            "BR": "https://client.us.freefiremobile.com/LikeProfile",
            "US": "https://client.us.freefiremobile.com/LikeProfile",
            "SAC": "https://client.us.freefiremobile.com/LikeProfile",
            "NA": "https://client.us.freefiremobile.com/LikeProfile"
        }
        like_url = url_map.get(server_name, url_map["ME"])

        # Send likes
        asyncio.run(send_multiple_requests(uid, server_name, like_url, total_requests=len(tokens)))

        # After likes
        after = make_request(encrypted_uid, server_name, token)
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
    return jsonify({"tokens": load_tokens()})


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
