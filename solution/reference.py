#!/usr/bin/env python3
"""出厂放行工位：核验厂商签发的许可证封套。"""

from __future__ import annotations

import datetime
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
SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
RSA_OID = bytes.fromhex("2a864886f70d010101")
SHA256_OID = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
MGF1_OID = bytes.fromhex("2a864886f70d010108")
PKCS1_V15_OID = bytes.fromhex("2a864886f70d01010b")
PSS_OID = bytes.fromhex("2a864886f70d01010a")
PSS_SALT_LENGTH = 32
PSS_TRAILER = 0xBC
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
HEX_DIGITS = set("0123456789abcdef")


class EnvelopeError(Exception):
    """封套不放行或编码不合规。"""


def read_length(data, offset):
    if offset >= len(data):
        raise EnvelopeError("长度字段不完整")
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    count = first & 0x7F
    if count == 0:
        raise EnvelopeError("不允许不定长编码")
    if offset + 1 + count > len(data):
        raise EnvelopeError("长度字段不完整")
    raw = data[offset + 1: offset + 1 + count]
    if raw[0] == 0:
        raise EnvelopeError("长形式长度带冗余前导零")
    value = int.from_bytes(raw, "big")
    if value < 0x80:
        raise EnvelopeError("短长度用了长形式")
    return value, offset + 1 + count


def read_tlv(data, offset, tag, label):
    if offset >= len(data):
        raise EnvelopeError("缺少 %s" % label)
    actual = data[offset]
    if actual != tag:
        raise EnvelopeError("%s 的标签应为 0x%02X，实际为 0x%02X" % (label, tag, actual))
    if tag & 0x1F == 0x1F:
        raise EnvelopeError("%s 使用了多字节标签" % label)
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
    if cursor != len(data):
        raise EnvelopeError("末段之后还有多余字节")
    return children


def read_any_tlv(data, offset, label):
    if offset >= len(data):
        raise EnvelopeError("%s 缺失" % label)
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise EnvelopeError("%s 使用了多字节标签" % label)
    length, cursor = read_length(data, offset + 1)
    end = cursor + length
    if end > len(data):
        raise EnvelopeError("%s 的内容长度越界" % label)
    return tag, data[cursor:end], end


def read_oid(content, label):
    if not content:
        raise EnvelopeError("%s 的 OID 为空" % label)
    if content[-1] & 0x80:
        raise EnvelopeError("%s 的 OID 没有写完" % label)
    index = 0
    while index < len(content):
        if content[index] == 0x80:
            raise EnvelopeError("%s 的 OID 带了冗余前导字节" % label)
        while index < len(content) and content[index] & 0x80:
            index += 1
        index += 1
    return content


def parse_algorithm_identifier(content, label):
    identifier, cursor = read_tlv(content, 0, 0x06, label)
    tag, parameters, cursor = read_any_tlv(content, cursor, label + ".parameters")
    if cursor != len(content):
        raise EnvelopeError("%s 之后还有多余字节" % label)
    return read_oid(identifier, label), tag, parameters


def parse_pss_parameters(params):
    cursor = 0
    fields = {}
    for tag, label in ((0xA0, "hashAlgorithm"), (0xA1, "maskGenAlgorithm"),
                       (0xA2, "saltLength"), (0xA3, "trailerField")):
        content, cursor = read_tlv(params, cursor, tag, "pss." + label)
        fields[label] = content
    if cursor != len(params):
        raise EnvelopeError("PSS 参数之后还有多余字节")
    (hash_algorithm,) = read_all(fields["hashAlgorithm"], (0x30,), ("pss.hashAlgorithm",))
    hash_oid, hash_tag, hash_params = parse_algorithm_identifier(hash_algorithm, "pss.hashAlgorithm")
    if hash_oid != SHA256_OID or hash_tag != 0x05 or hash_params != b"":
        raise EnvelopeError("PSS 的摘要算法必须是 SHA-256")
    (mask_algorithm,) = read_all(fields["maskGenAlgorithm"], (0x30,), ("pss.maskGenAlgorithm",))
    mgf_oid, mgf_tag, mgf_params = parse_algorithm_identifier(mask_algorithm, "pss.maskGenAlgorithm")
    if mgf_oid != MGF1_OID or mgf_tag != 0x30:
        raise EnvelopeError("PSS 的掩码算法必须是 MGF1")
    inner_oid, inner_tag, inner_params = parse_algorithm_identifier(mgf_params, "pss.mgf1")
    if inner_oid != SHA256_OID or inner_tag != 0x05 or inner_params != b"":
        raise EnvelopeError("PSS 的掩码摘要必须是 SHA-256")
    (salt_field,) = read_all(fields["saltLength"], (0x02,), ("pss.saltLength",))
    if read_integer(salt_field, "pss.saltLength") != PSS_SALT_LENGTH:
        raise EnvelopeError("PSS 的盐长度必须是 32")
    (trailer_field,) = read_all(fields["trailerField"], (0x02,), ("pss.trailerField",))
    if read_integer(trailer_field, "pss.trailerField") != 1:
        raise EnvelopeError("PSS 的 trailerField 必须是 1")
    return "rsassa-pss"


def parse_signature_algorithm(algorithm):
    oid, tag, params = parse_algorithm_identifier(algorithm, "signatureAlgorithm")
    if oid == PKCS1_V15_OID:
        if tag != 0x05 or params != b"":
            raise EnvelopeError("v1.5 的算法标识参数必须是 NULL")
        return "rsa-pkcs1-v1.5"
    if oid == PSS_OID:
        if tag != 0x30:
            raise EnvelopeError("PSS 的算法标识参数必须是序列")
        return parse_pss_parameters(params)
    raise EnvelopeError("不认识签名口径的算法标识")


def read_integer(content, label):
    if not content:
        raise EnvelopeError("%s 是空整数" % label)
    if content[0] & 0x80:
        raise EnvelopeError("%s 是负数" % label)
    if len(content) > 1 and content[0] == 0 and content[1] < 0x80:
        raise EnvelopeError("%s 带冗余前导零" % label)
    return int.from_bytes(content, "big")


def read_string(content, label):
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EnvelopeError("%s 不是合法 UTF-8" % label) from exc
    if not text:
        raise EnvelopeError("%s 不能为空" % label)
    return text


def read_bit_octets(content, label):
    if not content:
        raise EnvelopeError("%s 缺少未用位数" % label)
    unused = content[0]
    if unused > 7:
        raise EnvelopeError("%s 的未用位数非法" % label)
    if unused != 0:
        raise EnvelopeError("%s 的未用位不为零" % label)
    return content[1:]


def read_bit_list(content, label):
    """按 X.690 命名位表的最小形式读特性位图，返回置位的位号。"""
    if not content:
        raise EnvelopeError("%s 缺少未用位数" % label)
    unused = content[0]
    if unused > 7:
        raise EnvelopeError("%s 的未用位数非法" % label)
    octets = content[1:]
    if not octets:
        if unused != 0:
            raise EnvelopeError("%s 的未用位数非法" % label)
        return ()
    if not octets[-1] >> unused & 1:
        raise EnvelopeError("%s 的未用位数与最高置位不符" % label)
    if unused and octets[-1] & ((1 << unused) - 1):
        raise EnvelopeError("%s 的未用位不为零" % label)
    total = len(octets) * 8 - unused
    return tuple(
        index
        for index in range(total)
        if octets[index // 8] >> (7 - index % 8) & 1
    )


def parse_public_key(data):
    (outer,) = read_all(data, (0x30,), ("subjectPublicKeyInfo",))
    algorithm, key_bits = read_all(outer, (0x30, 0x03), ("algorithm", "subjectPublicKey"))
    identifier, parameters = read_all(
        algorithm, (0x06, 0x05), ("algorithmIdentifier", "parameters")
    )
    if read_oid(identifier, "公钥算法标识") != RSA_OID:
        raise EnvelopeError("公钥算法标识不是 RSA")
    if parameters != b"":
        raise EnvelopeError("公钥算法标识的 NULL 里带了字节")
    inner = read_bit_octets(key_bits, "subjectPublicKey")
    (rsa_key,) = read_all(inner, (0x30,), ("rsaPublicKey",))
    numbers = read_all(rsa_key, (0x02, 0x02), ("modulus", "publicExponent"))
    modulus = read_integer(numbers[0], "modulus")
    exponent = read_integer(numbers[1], "publicExponent")
    return modulus, exponent


def load_public_key(path):
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        raise EnvelopeError("无法读取公钥: %s" % exc) from exc
    return parse_public_key(data), data


def key_fingerprint(data):
    return hashlib.sha256(data).digest()[:8]


def read_extension_set(content, label):
    """按 DER 读 SET OF Extension：元素按编码字节升序，且不得重复。"""
    elements = []
    cursor = 0
    while cursor < len(content):
        if content[cursor] != 0x30:
            raise EnvelopeError("%s 的元素必须是序列" % label)
        length, body_start = read_length(content, cursor + 1)
        end = body_start + length
        if end > len(content):
            raise EnvelopeError("%s 的元素长度越界" % label)
        elements.append(content[cursor:end])
        cursor = end
    for index in range(1, len(elements)):
        if elements[index - 1] > elements[index]:
            raise EnvelopeError("%s 的元素没有按编码升序排列" % label)
        if elements[index - 1] == elements[index]:
            raise EnvelopeError("%s 里出现完全相同的两个元素" % label)
    identifiers = []
    for element in elements:
        (inner,) = read_all(element, (0x30,), (label + ".element",))
        numbers = read_all(inner, (0x02, 0x0C), (label + ".extId", label + ".extValue"))
        identifiers.append(read_integer(numbers[0], label + ".extId"))
        read_string(numbers[1], label + ".extValue")
    return identifiers


def parse_envelope(data):
    (outer,) = read_all(data, (0x30,), ("licenseEnvelope",))
    body_content, cursor = read_tlv(outer, 0, 0x30, "body")
    body_raw = outer[0:cursor]
    block, end = read_tlv(outer, cursor, 0x30, "signatureBlock")
    if end != len(outer):
        raise EnvelopeError("签名之后还有多余字节")
    algorithm, signature_bits = read_all(block, (0x30, 0x03), ("signatureAlgorithm", "signature"))
    return body_raw, algorithm, read_bit_octets(signature_bits, "signature")


def parse_body(raw):
    fields = {}
    (content,) = read_all(raw, (0x30,), ("licenseBody",))
    children = read_all(content, BODY_TAGS, BODY_NAMES)
    fields["version"] = read_integer(children[0], "version")
    fields["serial"] = read_string(children[1], "serial")
    fields["device_model"] = read_string(children[2], "deviceModel")
    fields["not_before"] = read_integer(children[3], "notBefore")
    fields["not_after"] = read_integer(children[4], "notAfter")
    fields["features"] = read_bit_list(children[5], "features")
    fields["authority"] = read_string(children[6], "authority")
    fields["key_id"] = children[7]
    fields["extensions"] = read_extension_set(children[8], "extensions")
    if len(fields["key_id"]) != 8:
        raise EnvelopeError("keyId 必须是 8 个字节")
    if fields["version"] != 1:
        raise EnvelopeError("version 只能为 1")
    for name in ("not_before", "not_after"):
        text = str(fields[name])
        if len(text) != 14 or not text.isdigit():
            raise EnvelopeError("%s 不是 14 位十进制时刻" % name)
        try:
            datetime.datetime.strptime(text, "%Y%m%d%H%M%S")
        except ValueError as exc:
            raise EnvelopeError("%s 不是一个存在的时刻" % name) from exc
    for name in ("serial", "device_model", "authority"):
        if not fields[name].strip():
            raise EnvelopeError("%s 是空白字符串" % name)
    return fields


def verify_signature(body, signature, modulus, exponent):
    key_bytes = (modulus.bit_length() + 7) // 8
    if len(signature) != key_bytes:
        raise EnvelopeError("签名长度与模数不符")
    value = int.from_bytes(signature, "big")
    if value >= modulus:
        raise EnvelopeError("签名数值超出模数")
    message = pow(value, exponent, modulus).to_bytes(key_bytes, "big")
    digest = hashlib.sha256(body).digest()
    padding = key_bytes - len(SHA256_PREFIX) - len(digest) - 3
    if padding < 8:
        raise EnvelopeError("模数太短")
    expected = b"\x00\x01" + b"\xff" * padding + b"\x00" + SHA256_PREFIX + digest
    if message != expected:
        raise EnvelopeError("签名与正文不符")


def mgf1(seed, length):
    mask = b""
    counter = 0
    while len(mask) < length:
        mask += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return mask[:length]


def verify_pss_signature(body, signature, modulus, exponent):
    key_bytes = (modulus.bit_length() + 7) // 8
    if len(signature) != key_bytes:
        raise EnvelopeError("签名长度与模数不符")
    value = int.from_bytes(signature, "big")
    if value >= modulus:
        raise EnvelopeError("签名数值超出模数")
    exponent_bytes = pow(value, exponent, modulus).to_bytes(key_bytes, "big")
    digest = hashlib.sha256(body).digest()
    em_bits = modulus.bit_length() - 1
    em_length = (em_bits + 7) // 8
    message = exponent_bytes[:em_length]
    leading = 8 * em_length - em_bits
    if leading and message[0] >> (8 - leading):
        raise EnvelopeError("PSS 的 EM 高位不为零")
    if message[-1] != PSS_TRAILER:
        raise EnvelopeError("PSS 的 trailer 字节不是 BC")
    masked = message[:em_length - len(digest) - 1]
    hashed = message[em_length - len(digest) - 1:em_length - 1]
    database = bytes(left ^ right for left, right in zip(masked, mgf1(hashed, len(masked))))
    if leading:
        database = bytes([database[0] & (0xFF >> leading)]) + database[1:]
    if len(database) < PSS_SALT_LENGTH + 1:
        raise EnvelopeError("PSS 的 EM 太短")
    split = len(database) - PSS_SALT_LENGTH - 1
    if database[:split] != b"\x00" * split or database[split] != 0x01:
        raise EnvelopeError("PSS 的定界串不符")
    salt = database[split + 1:]
    if hashlib.sha256(b"\x00" * 8 + digest + salt).digest() != hashed:
        raise EnvelopeError("PSS 的摘要不符")


def load_journal(path):
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise EnvelopeError("流水本子拿不到: %s" % exc) from exc
    if raw and not raw.endswith(b"\n"):
        raise EnvelopeError("流水里有不合规的行")
    records = []
    for physical in raw.splitlines(keepends=True):
        line = physical[:-1]
        if not line:
            raise EnvelopeError("流水里有不合规的行")
        try:
            text = line.decode("utf-8")
            document = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EnvelopeError("流水里有不合规的行") from exc
        if json.dumps(document, ensure_ascii=False, separators=(",", ":")) != text:
            raise EnvelopeError("流水里有不合规的行")
        if not isinstance(document, dict) or list(document) != ["at", "envelope_sha256", "result", "reason"]:
            raise EnvelopeError("流水里有不合规的行")
        moment_text = document["at"]
        digest = document["envelope_sha256"]
        result = document["result"]
        reason = document["reason"]
        if not isinstance(moment_text, str) or len(moment_text) != 14 or not moment_text.isdigit():
            raise EnvelopeError("流水里有不合规的行")
        if not isinstance(digest, str) or len(digest) != 64 or any(ch not in HEX_DIGITS for ch in digest):
            raise EnvelopeError("流水里有不合规的行")
        if result not in ("released", "rejected") or not isinstance(reason, str):
            raise EnvelopeError("流水里有不合规的行")
        if result == "released" and reason:
            raise EnvelopeError("流水里有不合规的行")
        if result == "rejected" and not reason:
            raise EnvelopeError("流水里有不合规的行")
        records.append(document)
    return records


def write_journal(path, records, stamp, digest_text, result, reason):
    for record in records:
        if record["envelope_sha256"] == digest_text and record["result"] == result:
            return records
    entry = {"at": stamp, "envelope_sha256": digest_text, "result": result, "reason": reason}
    with open(path, "a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")
    return records + [entry]


def summarize(records):
    latest = {}
    for record in records:
        latest[record["envelope_sha256"]] = record
    released = 0
    tally = {}
    for record in latest.values():
        if record["result"] == "released":
            released += 1
        else:
            tally[record["reason"]] = tally.get(record["reason"], 0) + 1
    ordered = sorted(tally.items(), key=lambda item: (-item[1], item[0].encode("utf-8")))
    return {
        "day": records[0]["at"][:8] if records else "",
        "released": released,
        "rejected": sum(tally.values()),
        "reasons": {reason: count for reason, count in ordered},
    }


def summary_text(records):
    return json.dumps(summarize(records), ensure_ascii=False, separators=(",", ":")) + "\n"


def load_summary(path):
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise EnvelopeError("小结拿不到: %s" % exc) from exc


def write_summary(path, records):
    with open(path, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(summary_text(records))


def load_revoked(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise EnvelopeError("吊销名单不可用: %s" % exc) from exc
    listed = set()
    for entry in text.splitlines():
        if len(entry) != 16 or any(ch not in HEX_DIGITS for ch in entry):
            raise EnvelopeError("吊销名单里有不合规的行")
        if entry in listed:
            raise EnvelopeError("吊销名单里有重复的密钥标识")
        listed.add(entry)
    return listed


class StampUnavailable(Exception):
    """放行时刻拿不到：这是题面里不必记账的那一种情况。"""


def release_moment():
    stamp = os.environ.get("RELEASE_STAMP")
    if not stamp:
        raise StampUnavailable("工位没有注入放行时刻")
    if len(stamp) != 14 or not stamp.isdigit():
        raise StampUnavailable("放行时刻格式不对")
    try:
        datetime.datetime.strptime(stamp, "%Y%m%d%H%M%S")
    except ValueError as exc:
        raise StampUnavailable("放行时刻不是存在的时刻") from exc
    return stamp


def release_model():
    model = os.environ.get("RELEASE_MODEL")
    if not model:
        raise EnvelopeError("工位没有注入当班机型")
    return model


def moment(text):
    return datetime.datetime.strptime(text, "%Y%m%d%H%M%S")


def feature_names(bitmap):
    names = []
    for index in bitmap:
        if index >= len(FEATURE_NAMES):
            raise EnvelopeError("位图出现未定义的第 %d 位" % index)
        names.append(FEATURE_NAMES[index])
    return names


def check(fields, stamp, model, revoked, fingerprint, sig_alg):
    if fields["key_id"] != fingerprint:
        raise EnvelopeError("密钥标识与公钥指纹不符")
    if fields["device_model"] != model:
        raise EnvelopeError("机型与当班型号不符")
    current = moment(stamp)
    if current < moment(str(fields["not_before"])) or current > moment(str(fields["not_after"])):
        raise EnvelopeError("封套不在有效期内")
    key_id = fields["key_id"].hex()
    if key_id in revoked:
        raise EnvelopeError("签发密钥已在吊销名单里")
    span = (moment(str(fields["not_after"])).date() - current.date()).days
    return {
        "serial": fields["serial"],
        "device_model": fields["device_model"],
        "not_before": str(fields["not_before"]),
        "not_after": str(fields["not_after"]),
        "features": feature_names(fields["features"]),
        "authority": fields["authority"],
        "key_id": key_id,
        "sig_alg": sig_alg,
        "remaining_days": span,
        "extensions": fields["extensions"],
    }


def main(argv):
    if len(argv) != 6:
        print("用法: license_check.py <封套文件> <公钥文件> <吊销名单文件> <报告文件> <流水文件>", file=sys.stderr)
        return 2
    report_path = argv[4]
    journal_path = argv[5]
    summary_path = journal_path + ".summary"
    stamp = None
    digest_text = None
    records = None
    try:
        with open(argv[1], "rb") as handle:
            data = handle.read()
        digest_text = hashlib.sha256(data).hexdigest()
        modulus, exponent = load_public_key(argv[2])[0]
        fingerprint = key_fingerprint(load_public_key(argv[2])[1])
        revoked = load_revoked(argv[3])
        try:
            stamp = release_moment()
        except StampUnavailable as exc:
            stamp = None
            stamp_problem = str(exc)
        else:
            stamp_problem = None
        records = load_journal(journal_path)
        if stamp_problem is not None:
            raise EnvelopeError(stamp_problem)
        model = release_model()
        for record in records:
            if record["at"][:8] != stamp[:8]:
                records = None
                raise EnvelopeError("流水里混着别的日期的记录")
        posted = load_summary(summary_path)
        if posted is not None and posted != summary_text(records).encode("utf-8"):
            records = None
            raise EnvelopeError("小结与这本流水对不上")
        body, algorithm, signature = parse_envelope(data)
        sig_alg = parse_signature_algorithm(algorithm)
        if sig_alg == "rsa-pkcs1-v1.5":
            verify_signature(body, signature, modulus, exponent)
        else:
            verify_pss_signature(body, signature, modulus, exponent)
        fields = parse_body(body)
        report = check(fields, stamp, model, revoked, fingerprint, sig_alg)
    except EnvelopeError as exc:
        print("封套不放行: %s" % exc, file=sys.stderr)
        if stamp is not None and digest_text is not None and records is not None:
            updated = write_journal(journal_path, records, stamp, digest_text, "rejected", str(exc))
            write_summary(summary_path, updated)
        return 3
    except OSError as exc:
        print("封套不放行: %s" % exc, file=sys.stderr)
        return 3
    with open(report_path, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(report, ensure_ascii=False, separators=(",", ":")) + "\n")
    updated = write_journal(journal_path, records, stamp, digest_text, "released", "")
    write_summary(summary_path, updated)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
