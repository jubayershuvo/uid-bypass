
import base64
import json
import re


def decode_hex_payload(hex_data: str):
    result = {
        "strings": [],
        "jwt": None,
        "urls": [],
        "ips": []
    }

    try:
        # HEX → bytes
        raw = bytes.fromhex(hex_data)

        # Extract readable ASCII strings
        strings = re.findall(rb"[ -~]{4,}", raw)
        decoded_strings = [s.decode(errors="ignore") for s in strings]

        result["strings"] = decoded_strings

        # 🔍 Find JWT
        for s in decoded_strings:
            if s.count(".") == 2 and s.startswith("ey"):
                try:
                    header_b64, payload_b64, signature = s.split(".")

                    def b64_decode(x):
                        x += "=" * (-len(x) % 4)
                        return json.loads(base64.urlsafe_b64decode(x).decode())

                    header = b64_decode(header_b64)
                    payload = b64_decode(payload_b64)

                    result["jwt"] = {
                        "token": s,
                        "header": header,
                        "payload": payload
                    }

                except Exception:
                    pass

        # 🌐 Extract URLs
        url_pattern = r"https?://[^\s]+"
        result["urls"] = re.findall(url_pattern, " ".join(decoded_strings))

        # 🌍 Extract IPs
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        result["ips"] = re.findall(ip_pattern, " ".join(decoded_strings))

    except Exception as e:
        print(f"❌ Decode error: {e}")

    return result



