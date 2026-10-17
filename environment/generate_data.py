#!/usr/bin/env python3
"""生成随题交付的放行演练数据：厂商公钥与四份许可证封套。

用法: python3 generate_data.py --out <目录>

签发用的私钥与公钥是一对固定的 1024 位演练密钥，只在本脚本里使用；
四份封套的字段取值固定，不含随机源，重复运行得到逐字节相同的产物。
"""

import argparse
import hashlib
import os

MODULUS = 124025479880674142102391122411730562924548448816958982264378745464117086919693630898230364091756458009868930110401794163763367835408982395752867102075037395309954716052170962851234619489361794446181807797990100167338102868145138174212109969572395069380140118221734427082160738258015782109017754956838567237759
EXPONENT = 65537
PRIVATE_EXPONENT = 67030570477340710030466660906411592517013382625031465459271787911241393696622494261490753255870939205480224979941583369401994121338879662748776305834838697889933743812980672333491889330729274969088404464286696451973769751335962811493874824075003282989725304155065106961614214211358768559034696167173295938113
SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
RSA_OID = bytes.fromhex("2a864886f70d010101")
SHA256_OID = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
MGF1_OID = bytes.fromhex("2a864886f70d010108")
PKCS1_V15_OID = bytes.fromhex("2a864886f70d01010b")
PSS_OID = bytes.fromhex("2a864886f70d01010a")
PSS_SALT = b"\x4d\x1c\x77\x02\x91\xbe\x35\x60\xa8\x0d\x13\xf4\x26\x9c\x08\x51"
PSS_SALT_TAIL = b"\xe2\x3b\x74\x90\x1f\x68\xc5\x22\x8a\x07\xdd\x31\x4f\x56\x9b\xa0"
KEY_ID_PLACEHOLDER = bytes(8)

SOURCE_NOTE = """放行工位用的四份演练封套来自产线样机：一份在有效期内，一份是去年那批已过期的旧证，\n一份是运输途中文件被截断后多带了一个字节的回读样本，还有一份是厂商换签名口径之后补发的同批次封套。\n厂商公钥就是当班工位刷入的那把。四份封套与公钥都由 environment/generate_data.py 这个生成脚本展开，\n脚本里的参数是固定的（种子 20261015 只是这批演练数据的批次编号），全程没有随机抽样；\n工位当天的吊销名单也一并放在这里，两行都是演练用的密钥标识。\n字段取值分布覆盖有效期内、已过期与结构损坏三类，签名口径覆盖 v1.5 与 PSS 两种。\n这些封套与密钥都是专门的演练数据，不含任何真实客户的设备序列号或密钥材料。\n"""


def der_length(value):
    if value < 0x80:
        return bytes([value])
    body = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag, content):
    return bytes([tag]) + der_length(len(content)) + content


def der_integer(value):
    if value == 0:
        return tlv(0x02, b"\x00")
    body = value.to_bytes((value.bit_length() + 8) // 8, "big", signed=True)
    return tlv(0x02, body)


def der_utf8(text):
    return tlv(0x0C, text.encode("utf-8"))


def der_bits(content, unused=0):
    return tlv(0x03, bytes([unused]) + content)


def der_octets(content):
    return tlv(0x04, content)


def extension(ext_id, value):
    return tlv(0x30, der_integer(ext_id) + der_utf8(value))


def der_set(elements):
    return tlv(0x31, b"".join(sorted(elements)))


def public_key_der():
    inner = tlv(0x30, der_integer(MODULUS) + der_integer(EXPONENT))
    algorithm = tlv(0x30, tlv(0x06, RSA_OID) + tlv(0x05, b""))
    return tlv(0x30, algorithm + der_bits(inner))


def mgf1(seed, length):
    mask = b""
    counter = 0
    while len(mask) < length:
        mask += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return mask[:length]


def pss_em(body):
    key_bytes = (MODULUS.bit_length() + 7) // 8
    digest = hashlib.sha256(body).digest()
    salt = PSS_SALT + PSS_SALT_TAIL
    hashed = hashlib.sha256(b"\x00" * 8 + digest + salt).digest()
    padding = b"\x00" * (key_bytes - len(hashed) - len(salt) - 2)
    database = padding + b"\x01" + salt
    masked = bytes(a ^ b for a, b in zip(database, mgf1(hashed, len(database))))
    masked = bytes([masked[0] & 0x7F]) + masked[1:]
    return masked + hashed + b"\xBC"


def pkcs1_algorithm():
    return tlv(0x30, tlv(0x06, PKCS1_V15_OID) + tlv(0x05, b""))


def pss_algorithm():
    parameters = tlv(0x30, b"".join((
        tlv(0xA0, tlv(0x30, tlv(0x06, SHA256_OID) + tlv(0x05, b""))),
        tlv(0xA1, tlv(0x30, tlv(0x06, MGF1_OID) + tlv(0x30, tlv(0x06, SHA256_OID) + tlv(0x05, b"")))),
        tlv(0xA2, der_integer(32)),
        tlv(0xA3, der_integer(1)),
    )))
    return tlv(0x30, tlv(0x06, PSS_OID) + parameters)


def sign(body):
    key_bytes = (MODULUS.bit_length() + 7) // 8
    digest = hashlib.sha256(body).digest()
    padding = key_bytes - len(SHA256_PREFIX) - len(digest) - 3
    message = b"\x00\x01" + b"\xff" * padding + b"\x00" + SHA256_PREFIX + digest
    value = pow(int.from_bytes(message, "big"), PRIVATE_EXPONENT, MODULUS)
    return value.to_bytes(key_bytes, "big")


def key_id():
    return hashlib.sha256(public_key_der()).digest()[:8]


def body_der(serial, model, not_before, not_after, features, unused):
    parts = (
        der_integer(1),
        der_utf8(serial),
        der_utf8(model),
        der_integer(not_before),
        der_integer(not_after),
        der_bits(bytes([features]), unused),
        der_utf8("Talents Instruments"),
        der_octets(key_id()),
        der_set([extension(3, "line-a"), extension(11, "rev-9")]),
    )
    return tlv(0x30, b"".join(parts))


def envelope_der(body, signature, algorithm=None, trailing=b""):
    block = tlv(0x30, (pkcs1_algorithm() if algorithm is None else algorithm) + der_bits(signature))
    return tlv(0x30, body + block) + trailing


REVOKED_NOTE = """7c21b48f0a5d3e61
b0e4ca2d5f8a1736
"""


def samples():
    fresh = body_der("SN-88214", "VX-300", 20260101000000, 20270101000000, 0x89, 0)
    expired = body_der("SN-73040", "VX-300", 20240101000000, 20250930000000, 0x24, 2)
    patched = body_der("SN-88214", "VX-300", 20260101000000, 20270101000000, 0x89, 0)
    renewal = body_der("SN-88214", "VX-300", 20260101000000, 20270101000000, 0x89, 0)
    return (
        ("press_line_a.der", envelope_der(fresh, sign(fresh))),
        ("press_line_b.der", envelope_der(expired, sign(expired))),
        ("press_line_c.der", envelope_der(patched, sign(patched), trailing=b"\x00")),
        ("press_line_d.der", envelope_der(renewal, pow(int.from_bytes(pss_em(renewal), "big"),
                                                    PRIVATE_EXPONENT, MODULUS).to_bytes(
            (MODULUS.bit_length() + 7) // 8, "big"), algorithm=pss_algorithm())),
    )


def main():
    parser = argparse.ArgumentParser(description="生成放行演练数据")
    parser.add_argument("--out", required=True, help="输出目录")
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "vendor_pub.der"), "wb") as stream:
        stream.write(public_key_der())
    for name, payload in samples():
        with open(os.path.join(args.out, name), "wb") as stream:
            stream.write(payload)
    with open(os.path.join(args.out, "revoked_keys.txt"), "w", encoding="utf-8", newline="\n") as stream:
        stream.write(REVOKED_NOTE)
    with open(os.path.join(args.out, "DATA_SOURCE.txt"), "w", encoding="utf-8", newline="\n") as stream:
        stream.write(SOURCE_NOTE)


if __name__ == "__main__":
    main()
