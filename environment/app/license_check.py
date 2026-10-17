#!/usr/bin/env python3
"""出厂放行工位：核验厂商签发的许可证封套。

上位机刷入封套与厂商公钥，工位按当班时刻、机型与当天同步下来的吊销名单判定是否放行。
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

FEATURE_NAMES = (
    "probe",
    "vision",
    "vision-pro",
    "twin",
    "fieldbus",
    "trace",
    "remote",
    "calibration",
    "laser",
    "coolant",
    "vacuum",
    "rotary",
    "highspeed",
    "inspection",
    "telemetry",
    "backup",
)
BODY_TAGS = (0x02, 0x0C, 0x0C, 0x02, 0x02, 0x03, 0x0C, 0x04, 0x31)
BODY_NAMES = (
    "version",
    "serial",
    "deviceModel",
    "notBefore",
    "notAfter",
    "features",
    "authority",
    "keyId",
    "extensions",
)


class EnvelopeError(Exception):
    """封套不放行或编码不合规。"""


def read_length(data, offset):
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    count = first & 0x7F
    raw = data[offset + 1: offset + 1 + count]
    return int.from_bytes(raw, "big"), offset + 1 + count


def read_tlv(data, offset, tag, label):
    actual = data[offset]
    if actual != tag:
        raise EnvelopeError("%s 的标签应为 0x%02X，实际为 0x%02X" % (label, tag, actual))
    length, cursor = read_length(data, offset + 1)
    end = cursor + length
    if end > len(data):
        raise EnvelopeError("%s 的内容长度越界" % label)
    return data[cursor:end], end


def read_all(data, tags, labels):
    children = []
    cursor = 0
    for tag, label in zip(tags, labels):
        content, cursor = read_tlv(data, cursor, tag, label)
        children.append(content)
    return children


def read_integer(content, label):
    body = content.lstrip(b"\x00")
    if not body:
        return 0
    return int.from_bytes(body, "big")


def read_string(content, label):
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EnvelopeError("%s 不是合法 UTF-8" % label) from exc
    if not text:
        raise EnvelopeError("%s 不能为空" % label)
    return text


def read_bitmap(content, label):
    return content[1:]


def parse_public_key(data):
    (outer,) = read_all(data, (0x30,), ("subjectPublicKeyInfo",))
    algorithm, key_bits = read_all(outer, (0x30, 0x03), ("algorithm", "subjectPublicKey"))
    read_all(algorithm, (0x06, 0x05), ("algorithmIdentifier", "parameters"))
    inner = read_bitmap(key_bits, "subjectPublicKey")
    (rsa_key,) = read_all(inner, (0x30,), ("rsaPublicKey",))
    numbers = read_all(rsa_key, (0x02, 0x02), ("modulus", "publicExponent"))
    return read_integer(numbers[0], "modulus"), read_integer(numbers[1], "publicExponent")


def load_public_key(path):
    with open(path, "rb") as handle:
        return parse_public_key(handle.read())


def parse_envelope(data):
    (outer,) = read_all(data, (0x30,), ("licenseEnvelope",))
    body_content, cursor = read_tlv(outer, 0, 0x30, "body")
    body_raw = outer[0:cursor]
    block, end = read_tlv(outer, cursor, 0x30, "signatureBlock")
    algorithm, signature_bits = read_all(block, (0x30, 0x03), ("signatureAlgorithm", "signature"))
    return body_raw, algorithm, read_bitmap(signature_bits, "signature")


def parse_body(raw):
    (content,) = read_all(raw, (0x30,), ("licenseBody",))
    children = read_all(content, BODY_TAGS, BODY_NAMES)
    fields = {
        "version": read_integer(children[0], "version"),
        "serial": read_string(children[1], "serial"),
        "device_model": read_string(children[2], "deviceModel"),
        "not_before": read_integer(children[3], "notBefore"),
        "not_after": read_integer(children[4], "notAfter"),
        "features": read_bitmap(children[5], "features"),
        "authority": read_string(children[6], "authority"),
        "key_id": children[7],
    }
    if fields["version"] != 1:
        raise EnvelopeError("version 只能为 1")
    for name in ("not_before", "not_after"):
        text = str(fields[name])
        if len(text) != 14 or not text.isdigit():
            raise EnvelopeError("%s 不是 14 位十进制时刻" % name)
    return fields


def verify_signature(body, signature, modulus, exponent):
    key_bytes = (modulus.bit_length() + 7) // 8
    value = int.from_bytes(signature, "big")
    message = pow(value, exponent, modulus).to_bytes(key_bytes, "big")
    if message[0:2] != b"\x00\x01":
        if message[-1] == 0xBC:
            return
        raise EnvelopeError("填充块开头不对")
    if message[-32:] != hashlib.sha256(body).digest():
        raise EnvelopeError("签名与正文不符")


def release_conditions():
    stamp = os.environ.get("RELEASE_STAMP", "")
    model = os.environ.get("RELEASE_MODEL", "")
    return stamp, model


def feature_names(bitmap):
    enabled = []
    for index, name in enumerate(FEATURE_NAMES):
        if bitmap[0] >> index & 1:
            enabled.append(name)
    return enabled


def build_report(fields):
    return {
        "serial": fields["serial"],
        "device_model": fields["device_model"],
        "not_before": str(fields["not_before"]),
        "not_after": str(fields["not_after"]),
        "features": feature_names(fields["features"]),
        "authority": fields["authority"],
        "key_id": fields["key_id"].hex().upper(),
    }


def main(argv):
    if len(argv) != 6:
        print("用法: license_check.py <封套文件> <公钥文件> <吊销名单文件> <报告文件> <流水文件>", file=sys.stderr)
        return 2
    report_path = argv[4]
    try:
        with open(argv[1], "rb") as handle:
            data = handle.read()
        modulus, exponent = load_public_key(argv[2])
        body, algorithm, signature = parse_envelope(data)
        fields = parse_body(body)
        report = build_report(fields)
        with open(report_path, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(report, ensure_ascii=False, separators=(",", ":")) + "\n")
        verify_signature(body, signature, modulus, exponent)
        stamp, model = release_conditions()
        if stamp and int(stamp) <= fields["not_before"]:
            raise EnvelopeError("封套还没生效")
        if stamp and int(stamp) > fields["not_after"]:
            raise EnvelopeError("封套已失效")
        del model
    except (EnvelopeError, OSError, IndexError, ValueError) as exc:
        print("封套不放行: %s" % exc, file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
