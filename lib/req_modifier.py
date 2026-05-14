import blackboxprotobuf
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

AES_KEY = b"Yg&tc%DEuh6%Zc^8"
AES_IV = b"6oyZDr22E3ychjM%"

# default modifications - 100% mobile (Samsung SM-S928B / Galaxy S24 Ultra)
DEFAULT_MODS = {
#   8: "Android OS 13 / API-33 (SP1A.210812.016/R.1ab9c02-18618)",
#   9: "Handheld",
#   11: "WIFI",
  12: 1600,
  13: 720,
#   14: "272",
  15: "ARM64 FP ASIMD AES | 2000 | 8",
#   16: 3736,
  17: "Mali-G52 MC2",
  18: "OpenGL ES 3.2 v1.r32p1-01eac0.2a893c04ca0026c2e6802dbe7d7af5c5",
#   19: "Google|5340e1ed-87e3-4a48-ae61-1b673844b03a",
#   21: "en",
#   23: "4",
#   24: "Handheld",
#   25: "realme RMX3195",
#   30: 1,
#   42: "WIFI",
#   57: "7428b253defc164018c604a1ebbfebdf",
#   60: 108094,
#   61: 95691,
#   62: 765,
#   64: 96215,
#   65: 108094,
#   66: 96215,
#   67: 108094,
#   73: 3,
#   74: "/data/app/~~pXNxJEKVOPaiyHsFpQzMMA==/com.dts.freefireth-DVtjeaEy6yPosgaMbMxyoQ==/lib/arm64",
#   76: 1,
#   77: "17e6a447803a17e4f59e3fd734efc5ae|/data/app/~~pXNxJEKVOPaiyHsFpQzMMA==/com.dts.freefireth-DVtjeaEy6yPosgaMbMxyoQ==/base.apk",
#   78: 3,
#   79: 2,
#   81: "64",
#   83: "2019120270",
#   85: 3,
#   86: "OpenGLES2",
#   87: 255,
#   88: 4,
#   92: 8513,
#   93: "android",
#   94: "KqsHT9NQ67flm7UCirfq0GJ1JKxYDPEcgL3nJC174IBBMheP+cGcngMUwS4R88wSKzdPBxa/6+ADit2OLkwDAenmhtU=",
  94: "KqsHT7znl8pCvd8jrQoqKyrp3VRiQgXKIJuLmJBrqp5bOEbr4hnY9INfLUOyUbVu94ZduTXaq/0mEtpYKO5wvHCvlnA=",
#   95: 111107,
#   97: 1,
  102: {
    8: 3914200987611644931
  }
}

def modify_hex(hex_data: str, mods: dict = DEFAULT_MODS) -> str:
    try:
        # decrypt
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        decrypted = cipher.decrypt(bytes.fromhex(hex_data))

        try:
            decrypted = unpad(decrypted, AES.block_size)
        except:
            pass

        # decode
        decoded, msg_type = blackboxprotobuf.decode_message(decrypted)

        # modify
        for k, v in mods.items():
            decoded[str(k)] = v

        # encode
        protobuf = blackboxprotobuf.encode_message(decoded, msg_type)

        # encrypt
        padded = pad(protobuf, AES.block_size)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        encrypted = cipher.encrypt(padded)

        return encrypted.hex()

    except Exception as e:
        print("Modify error:", e)
        return hex_data