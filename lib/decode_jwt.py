import base64
import json


def decode_jwt(token: str):
    try:
        header_b64, payload_b64, signature = token.split(".")

        def b64_decode(data):
            # Fix padding
            data += "=" * (-len(data) % 4)
            return json.loads(base64.urlsafe_b64decode(data).decode())

        header = b64_decode(header_b64)
        payload = b64_decode(payload_b64)

        return {
            "header": header,
            "payload": payload,
            "signature": signature
        }

    except Exception as e:
        print(f"❌ Decode error: {e}")
        return None