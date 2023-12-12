import hmac
from base64 import b64decode, b64encode
from hashlib import sha1
from urllib import parse

from Member.utils.secure.easyRSA import easyRSA
import time

from AlfredWiki.settings import MONGO
from pymongo import MongoClient
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def sessionKeyGenerate():
    return easyRSA().session_key()


def sessionDecrypted(data_encrypted, session_private_key):
    data_encrypted = parse.unquote(data_encrypted)
    data_encrypted = b64decode(data_encrypted)

    results = {
        "status": "Success",
        "info": ""
    }

    try:
        results["info"] = b64decode(easyRSA().session_decrypted(
            data_encrypted, session_private_key.encode())).decode()
    except:
        results["status"] = "Fail"

    return results


def hmacsha(playerid, pass_ori):
    return hmac.new(playerid.encode(), pass_ori.encode(), sha1).hexdigest()


def log_rec(request):
    client = MongoClient(MONGO)

    rec_time = time.time()
    saved_log = {
        "connect":  {
            "scheme": request.scheme,
            "is_secure": request.is_secure(),
            "host": request.get_host(),
            "port": request.get_port(),
            "full_path_info": request.get_full_path_info(),
            "method": request.method,
        },
        "username": request.user.username,
        "rec_time": rec_time,
        "headers": {}
    }

    for k, v in request.headers.items():
        if k not in ["Cf-Ipcountry", "Cf-Connecting-Ip", "X-Forwarded-For", "User-Agent"]:
            saved_log["headers"][k] = v
            continue

        res_dict = easyRSA().encrypt(secret_code=str(int(rec_time)), oriText=v)

        sid = client['security']['infos'].insert_one({
            "public_key": res_dict["public_key"],
            "private_encrypted": res_dict["private_encrypted"],
            "enc_session_key": res_dict["enc_session_key"],
            "nonce": res_dict["nonce"],
            "tag": res_dict["tag"],
            "ciphertext_bin": res_dict["ciphertext_bin"],
            "ciphertext_hex": res_dict["ciphertext_hex"],
        }).inserted_id

        saved_log["headers"][k] = sid

    client['security']["log"].insert_one(saved_log)

    client.close()


def aes_encrypt(message):
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(
        b64encode(message.encode()))
    nonce = cipher.nonce

    client = MongoClient(MONGO)

    inserted_id = client['security']['infos'].insert_one({
        "key": key,
        "ciphertext": ciphertext.hex(),
        "nonce": nonce.hex(),
        "tag": tag.hex(),
    }).inserted_id

    client.close()

    return inserted_id


def aes_decrypt(key, nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=bytes.fromhex(nonce))
    decrypted_message = cipher.decrypt_and_verify(
        bytes.fromhex(ciphertext), bytes.fromhex(tag))
    return b64decode(decrypted_message).decode()
