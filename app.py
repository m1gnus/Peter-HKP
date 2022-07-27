from flask import Flask, request, make_response
import urllib.parse
import gnupg
import re

app = Flask(__name__)

ABS_PATH = "/pks/lookup"
ACCEPTED_VARIABLES = ("op", "search", "options", "fingerprint", "exact")
ACCEPTED_KEY_ID_LENGTH = (8, 16, 32, 40)
KEY_ID_PREFIX = "0x"
VALID_OPERATIONS = ("get")

HEX_RE = re.compile("^[a-fA-F0-9]+$")

gpg = gnupg.GPG()

@app.get("/pks/lookup")
def key_lookup():
    if any(param not in ACCEPTED_VARIABLES for param in request.args):
        return "", 501

    if any(param not in request.args for param in ("op", "search")):
        return "" ,400

    op = request.args.get("op").casefold()
    search = request.args.get("search").casefold()

    if any(request.args.get(param, "off").casefold() not in ("on", "off") for param in ("fingerprint", "exact")):
        return "", 400

    machine_readable = request.args.get("options", "").casefold() == "mr"
    fingerprint = request.args.get("fingerprint", "").casefold() == "on"
    exact = request.args.get("exact", "").casefold() == "on"

    if op == "get":
        result = None

        if search.startswith(KEY_ID_PREFIX):
            search = search.lstrip("0x")
            s_length = len(search)

            if s_length not in ACCEPTED_KEY_ID_LENGTH:
                return "", 400

            # search by keyid or fingerprint?
            keyid = s_length in (8, 16)
            for key in gpg.list_keys():
                if key.get("keyid").casefold().startswith(search):
                    result = key
                    break

        else:
            # Implement text search
            for key in gpg.list_keys():
                if any(search in uid for uid in key.get("uids")):
                    result = key

        if result:
            response =  make_response(f"\n{gpg.export_keys(result.get('keyid'))}\n", 200)
            response.headers['Content-Type'] = "application/pgp-keys"
            return response

        return "", 404

    elif op == "index":
        results = []

        if search.startswith(KEY_ID_PREFIX):
            search = search.lstrip("0x")
            for key in gpg.list_keys():
                if any(search in target for target in (key.keyid, key.fingerprint)):
                    results.append(key)

        else:
            for key in gpg.list_keys():
                if any(search in uid for uid in key.get("uids")):
                    results.append(key)

        if not results:
            return "", 404

        result = f"info:1:{len(results)}\n"
        for res in results:
            result += f"pub:{res.get('keyid')}:{res.get('algo')}:{res.get('date')}:{res.get('expires')}"
            if (flag := res.get("flag")):
                result += f":{flag}"
            result += "\n"
            for uid in res.get("uids"):
                result += f"uid:{urllib.parse.quote_plus(uid)}:{res.get('date')}:{res.get('expires')}"
                if (flag := res.get("flag")):
                    result += f":{flag}"
                result += "\n"

        return result, 200

    elif op == "vindex":
        return "", 501
    else:
        return "", 501
