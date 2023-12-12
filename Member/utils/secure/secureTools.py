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
