"""行为验收：出厂放行工位的许可证封套核验契约。"""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

APP = Path(os.environ.get("TASK_APP", "/app/license_check.py"))
DATA = Path(os.environ.get("TASK_DATA_DIR", "/data"))
CALL_TIMEOUT_SEC = 60

MODULUS = 124025479880674142102391122411730562924548448816958982264378745464117086919693630898230364091756458009868930110401794163763367835408982395752867102075037395309954716052170962851234619489361794446181807797990100167338102868145138174212109969572395069380140118221734427082160738258015782109017754956838567237759
EXPONENT = 65537
PRIVATE_EXPONENT = 67030570477340710030466660906411592517013382625031465459271787911241393696622494261490753255870939205480224979941583369401994121338879662748776305834838697889933743812980672333491889330729274969088404464286696451973769751335962811493874824075003282989725304155065106961614214211358768559034696167173295938113
SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
RSA_OID = bytes.fromhex("2a864886f70d010101")
KEY_BYTES = (MODULUS.bit_length() + 7) // 8

VALID_ENVELOPE = "envelope_valid"
PADDED_LENGTH = "envelope_padded-length"
LONG_FORM = "envelope_long-form"
PADDED_INTEGER = "envelope_padded-integer"
UNUSED_BITS = "envelope_unused-bits"
TRAILING_BYTE = "envelope_trailing-byte"
SHORT_KEY_ID = "envelope_short-keyid"
FOREIGN_PREFIX = "envelope_foreign-prefix"
BROKEN_PADDING = "envelope_broken-padding"
STALE_SIGNATURE = "envelope_stale-signature"
NOT_A_SEQUENCE = "envelope_not-a-sequence"
MISSING_FIELD = "envelope_missing-field"
OLD_VERSION = "envelope_old-version"
RELEASE_STAMP = "20260601120000"
RELEASE_MODEL = "VX-300"
NOT_BEFORE = 20260101000000
NOT_AFTER = 20270101000000
FEATURE_BITS = 0x89
EMPTY_BITS = 0x00
WIDE_BITS = (b"\x01\x08", 3)
REVOKED_KEYS = "7c21b48f0a5d3e61\n"


def _der_length(value):
    if value < 0x80:
        return bytes([value])
    body = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag, content):
    return bytes([tag]) + _der_length(len(content)) + content


def _tlv_padded_length(tag, content):
    return bytes([tag, 0x82]) + len(content).to_bytes(2, "big") + content


def _tlv_long_form_length(tag, content):
    return bytes([tag, 0x81]) + bytes([len(content)]) + content


def _int(value):
    if value == 0:
        return _tlv(0x02, b"\x00")
    body = value.to_bytes((value.bit_length() + 8) // 8, "big", signed=True)
    return _tlv(0x02, body)


def _utf8(text):
    return _tlv(0x0C, text.encode("utf-8"))


def _bits(content, unused=0):
    return _tlv(0x03, bytes([unused]) + content)


def _octets(data):
    return _tlv(0x04, data)


def _seq(parts):
    return _tlv(0x30, b"".join(parts))


def _extension(ext_id, value):
    return _seq([_int(ext_id), _utf8(value)])


def _extensions(elements):
    return _tlv(0x31, b"".join(elements))


DEFAULT_EXTENSIONS = [_extension(11, "rev-9"), _extension(3, "line-a")]


def _default_parts():
    return [
        _int(1),
        _utf8("SN-88214"),
        _utf8("VX-300"),
        _int(NOT_BEFORE),
        _int(NOT_AFTER),
        _bits(bytes([FEATURE_BITS])),
        _utf8("Talents Instruments"),
        _octets(KEY_ID),
        _extensions(DEFAULT_EXTENSIONS),
    ]


def _body(parts=None):
    return _seq(_default_parts() if parts is None else parts)


def _signature_for(body):
    digest = hashlib.sha256(body).digest()
    padding = KEY_BYTES - len(SHA256_PREFIX) - len(digest) - 3
    message = b"\x00\x01" + b"\xff" * padding + b"\x00" + SHA256_PREFIX + digest
    return pow(int.from_bytes(message, "big"), PRIVATE_EXPONENT, MODULUS).to_bytes(KEY_BYTES, "big")


PSS_OID = bytes.fromhex("2a864886f70d01010a")
PKCS1_V15_OID = bytes.fromhex("2a864886f70d01010b")
SHA1_OID = bytes.fromhex("2b0e03021a")
SHA256_OID = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
MGF1_OID = bytes.fromhex("2a864886f70d010108")
PSS_SALT_LENGTH = 32


def _oid(raw):
    return _tlv(0x06, raw)


def _null():
    return _tlv(0x05, b"")


def _explicit(tag, content):
    return _tlv(tag, content)


def _v15_algorithm(oid=PKCS1_V15_OID, params=None):
    return _seq([_oid(oid), _null() if params is None else params])


def _pss_algorithm(salt=32, trailer=1, hash_oid=SHA256_OID, mgf_hash_oid=SHA256_OID,
                   mgf_params=None, mgf_oid=MGF1_OID, omit=(), order=(0xA0, 0xA1, 0xA2, 0xA3),
                   salt_field=None):
    mask_params = _seq([_oid(mgf_hash_oid), _null()]) if mgf_params is None else mgf_params
    fields = {
        0xA0: _explicit(0xA0, _seq([_oid(hash_oid), _null()])),
        0xA1: _explicit(0xA1, _seq([_oid(mgf_oid), mask_params])),
        0xA2: _explicit(0xA2, _int(salt) if salt_field is None else salt_field),
        0xA3: _explicit(0xA3, _int(trailer)),
    }
    return _seq([_oid(PSS_OID), _seq([fields[tag] for tag in order if tag not in omit])])


def _sign_em(em):
    """把任意 EM 字节串用演练私钥签成签名值（用于构造各种 EM 形状）。"""
    return pow(int.from_bytes(em, "big"), PRIVATE_EXPONENT, MODULUS).to_bytes(KEY_BYTES, "big")


def _mgf1(seed, length, hash_oid=SHA256_OID):
    digestmod = hashlib.sha256 if hash_oid == SHA256_OID else hashlib.sha1
    mask = b""
    counter = 0
    while len(mask) < length:
        mask += digestmod(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return mask[:length]


def _pss_em(body, salt=None, hash_salt=None, salt_length=PSS_SALT_LENGTH, delimiter=0x01,
            trailer=0xBC, mgf_hash_oid=SHA256_OID, em_length=None, clear_top=True):
    digest = hashlib.sha256(body).digest()
    length = KEY_BYTES if em_length is None else em_length
    salt = (b"\x11" * salt_length) if salt is None else salt
    checked_salt = salt if hash_salt is None else hash_salt
    hashed = hashlib.sha256(b"\x00" * 8 + digest + checked_salt).digest()
    padding = b"\x00" * (length - len(hashed) - len(salt) - 2)
    database = padding + bytes([delimiter]) + salt
    masked = bytes(a ^ b for a, b in zip(database, _mgf1(hashed, len(database), mgf_hash_oid)))
    if clear_top:
        masked = bytes([masked[0] & 0x7F]) + masked[1:]
    return masked + hashed + bytes([trailer])


def _pss_signature(body, **knobs):
    return _sign_em(_pss_em(body, **knobs))


def _forge(message_block):
    return pow(int.from_bytes(message_block, "big"), PRIVATE_EXPONENT, MODULUS).to_bytes(KEY_BYTES, "big")


def _envelope(body, signature=None, outer=None, trailing=b"", signature_unused=0, extra=b"",
              algorithm=None, raw_signature_element=None):
    signed = _signature_for(body) if signature is None else signature
    if raw_signature_element is None:
        block = _seq([_v15_algorithm() if algorithm is None else algorithm,
                      _bits(signed, unused=signature_unused)])
    else:
        block = raw_signature_element
    payload = body + block + extra
    packed = _tlv(0x30, payload) if outer is None else outer(0x30, payload)
    return packed + trailing


def _public_key_bytes():
    inner = _seq([_int(MODULUS), _int(EXPONENT)])
    algorithm = _seq([_tlv(0x06, RSA_OID), _tlv(0x05, b"")])
    return _seq([algorithm, _bits(inner)])


KEY_ID = hashlib.sha256(_public_key_bytes()).digest()[:8]


def _write(path, payload):
    path.write_bytes(payload)
    return path


def _run(envelope, key, revoked, report, journal, stamp=RELEASE_STAMP, model=RELEASE_MODEL):
    env = {name: value for name, value in os.environ.items() if not name.startswith("PYTEST")}
    env["RELEASE_STAMP"] = stamp
    env["RELEASE_MODEL"] = model
    return subprocess.run(
        [sys.executable, str(APP), str(envelope), str(key), str(revoked), str(report), str(journal)],
        capture_output=True,
        text=True,
        timeout=CALL_TIMEOUT_SEC,
        env=env,
    )


def _run_without_environment(envelope, key, revoked, report, journal):
    env = {name: value for name, value in os.environ.items()
           if name not in ("RELEASE_STAMP", "RELEASE_MODEL") and not name.startswith("PYTEST")}
    return subprocess.run(
        [sys.executable, str(APP), str(envelope), str(key), str(revoked), str(report), str(journal)],
        capture_output=True,
        text=True,
        timeout=CALL_TIMEOUT_SEC,
        env=env,
    )


def _prepare(tmp_path, name, payload, key_payload=None, revoked_text=REVOKED_KEYS, revoked_name=None):
    envelope = _write(tmp_path / (name + ".der"), payload)
    key = _write(tmp_path / (name + ".pub"), _public_key_bytes() if key_payload is None else key_payload)
    revoked = tmp_path / ((revoked_name or name) + ".revoked")
    revoked.write_text(revoked_text, encoding="utf-8")
    return envelope, key, revoked, tmp_path / (name + ".json"), tmp_path / (name + ".journal")


def _report(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_rejects_length_with_redundant_leading_zero(tmp_path):
    """题面「长度字段取最短形式」：长形式的长度里带冗余前导零就拒收。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, PADDED_LENGTH, _envelope(_body(), outer=_tlv_padded_length))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_long_form_length_for_short_value(tmp_path):
    """题面「短于 128 的字节数不许写成两字节以上的长形式」：正文里的机构名用了长形式。"""
    parts = _default_parts()
    parts[6] = _tlv_long_form_length(0x0C, "Talents Instruments".encode("utf-8"))
    envelope, key, revoked, report, journal = _prepare(tmp_path, LONG_FORM, _envelope(_body(parts)))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_integer_with_redundant_leading_zero(tmp_path):
    """题面「非负数不许带多余的前导零字节」：版本号整数多带了一个零字节。"""
    parts = _default_parts()
    parts[0] = _tlv(0x02, b"\x00\x01")
    envelope, key, revoked, report, journal = _prepare(tmp_path, PADDED_INTEGER, _envelope(_body(parts)))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_bit_string_with_unused_bits(tmp_path):
    """题面「它的未用位数是零」：签名位串的未用位数写成 1。"""
    parts = _default_parts()
    envelope, key, revoked, report, journal = _prepare(tmp_path, UNUSED_BITS, _envelope(_body(), signature_unused=1))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_envelope_with_trailing_byte(tmp_path):
    """题面「序列里不要再拖别的东西」：封套末尾多带一个字节就拒收。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, TRAILING_BYTE, _envelope(_body(), trailing=b"\x00"))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_sequence_tag_without_length_byte(tmp_path):
    """题面「长度字段取最短形式」：序列标签后连长度字节都缺时按封套不放行处理。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_missing-length", b"\x30")
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3
    assert result.stderr.strip().startswith("封套不放行: ")
    assert not report.exists()


def test_rejects_digest_block_with_foreign_prefix(tmp_path):
    """题面「后 32 个字节是正文的 SHA-256」：摘要块挂着别的算法的前缀就拒收。"""
    body = _body()
    digest = hashlib.sha256(body).digest()
    foreign = bytes.fromhex("3021300906052b0e03021a05000414")
    message = b"\x00\x01" + b"\xff" * (KEY_BYTES - len(foreign) - len(digest) - 3) + b"\x00" + foreign + digest
    envelope, key, revoked, report, journal = _prepare(tmp_path, FOREIGN_PREFIX, _envelope(body, signature=_forge(message)))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_broken_pkcs1_padding(tmp_path):
    """题面「逐字节对照 PKCS#1 v1.5 的结构」：填充块用别的字节就拒收。"""
    body = _body()
    digest = hashlib.sha256(body).digest()
    padding = KEY_BYTES - len(SHA256_PREFIX) - len(digest) - 3
    message = b"\x00\x01" + b"\x00" * padding + b"\x00" + SHA256_PREFIX + digest
    envelope, key, revoked, report, journal = _prepare(tmp_path, BROKEN_PADDING, _envelope(body, signature=_forge(message)))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_signature_mismatch(tmp_path):
    """题面「签名是对正文元素本身的字节做的」：正文被改过之后签名对不上。"""
    parts = _default_parts()
    parts[1] = _utf8("SN-99999")
    tampered = _body(parts)
    envelope, key, revoked, report, journal = _prepare(tmp_path, STALE_SIGNATURE, _envelope(tampered, signature=_signature_for(_body())))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_envelope_without_sequence_tag(tmp_path):
    """题面「封套是 DER 编码的一个序列」：最外层不是序列就拒收。"""
    payload = _envelope(_body())
    envelope, key, revoked, report, journal = _prepare(tmp_path, NOT_A_SEQUENCE, b"\x31" + payload[1:])
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_body_with_missing_field(tmp_path):
    """题面「正文也是一个序列，字段按下表排」：正文少一个字段就拒收。"""
    parts = _default_parts()
    del parts[8]
    envelope, key, revoked, report, journal = _prepare(tmp_path, MISSING_FIELD, _envelope(_body(parts)))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_unsupported_version(tmp_path):
    """题面「版本号，取 1」：版本号不是 1 就拒收。"""
    parts = _default_parts()
    parts[0] = _int(2)
    envelope, key, revoked, report, journal = _prepare(tmp_path, OLD_VERSION, _envelope(_body(parts)))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_broken_public_key_file(tmp_path):
    """题面「最外面一个序列，里面先是算法标识序列」：公钥文件结构不对就拒收。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_broken-key", _envelope(_body()), key_payload=b"\x30\x00")
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_release_stamp_outside_validity(tmp_path):
    """题面「放行时刻落在 notBefore 与 notAfter 之间」：早于生效时刻就拒收。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_early-stamp", _envelope(_body()))
    result = _run(envelope, key, revoked, report, journal, stamp="20251231000000")
    assert result.returncode == 3


def test_rejects_envelope_for_another_model(tmp_path):
    """题面「机型代号与 RELEASE_MODEL 相同」：当班机型换成别的型号就拒收。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_other-model", _envelope(_body()))
    result = _run(envelope, key, revoked, report, journal, model="HX-900")
    assert result.returncode == 3


def test_rejects_missing_release_environment(tmp_path):
    """题面「这两个变量少一个，设备就放行不了」：工位没注入放行条件就拒收。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_no-environment", _envelope(_body()))
    result = _run_without_environment(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_accepts_release_stamp_on_lower_boundary(tmp_path):
    """题面「两端当天都算在有效期内」：放行时刻正好是生效时刻也放行。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_lower-boundary", _envelope(_body()))
    result = _run(envelope, key, revoked, report, journal, stamp=str(NOT_BEFORE))
    assert result.returncode == 0
    assert report.is_file()


def test_accepts_release_stamp_on_upper_boundary(tmp_path):
    """题面「两端当天都算在有效期内」：放行时刻正好是失效时刻也放行。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_upper-boundary", _envelope(_body()))
    result = _run(envelope, key, revoked, report, journal, stamp=str(NOT_AFTER))
    assert result.returncode == 0
    assert report.is_file()


def test_reports_features_by_asn1_bit_order(tmp_path):
    """题面「第 0 位是第一个字节的最高位」：位图 0x05 对应 trace 与 calibration。"""
    parts = _default_parts()
    parts[5] = _bits(bytes([0x05]))
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_feature-order", _envelope(_body(parts)))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 0
    assert _report(report)["features"] == ["trace", "calibration"]


def test_reports_key_identifier_in_lowercase_hex(tmp_path):
    """题面「key_id 是那 8 个字节的小写十六进制」：报告的密钥标识全是小写。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_keyid-case", _envelope(_body()))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 0
    assert _report(report)["key_id"] == KEY_ID.hex()


def test_rejection_leaves_existing_report_untouched(tmp_path):
    """题面「那条路径上如果留着上一次的放行记录，也不许动它」：被拒时不动旧报告。"""
    parts = _default_parts()
    parts[1] = _utf8("SN-99999")
    payload = _envelope(_body(parts), signature=_signature_for(_body()))
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_stale-report", payload)
    report.write_bytes(b"OLD-RELEASE-RECORD\n")
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3
    assert report.read_bytes() == b"OLD-RELEASE-RECORD\n"


def test_accepts_valid_envelope_and_writes_report(tmp_path):
    """题面「表示核验通过」：合法封套放行并把报告写出来。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, VALID_ENVELOPE, _envelope(_body()))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 0
    assert report.is_file()


def test_report_keeps_field_order(tmp_path):
    """题面「字段按 serial、device_model、not_before、not_after、features、authority、key_id、sig_alg、remaining_days、extensions 的顺序排」：报告字段顺序固定。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_report-order", _envelope(_body()))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 0
    document = _report(report)
    assert list(document) == [
        "serial",
        "device_model",
        "not_before",
        "not_after",
        "features",
        "authority",
        "key_id",
        "sig_alg",
        "remaining_days",
        "extensions",
    ]
    assert document["sig_alg"] == "rsa-pkcs1-v1.5"
    assert document["serial"] == "SN-88214"
    assert document["not_before"] == "20260101000000"
    assert document["authority"] == "Talents Instruments"


def test_reports_empty_feature_list_when_bitmap_empty(tmp_path):
    """题面「features 是已开通的特性名数组」：一个特性都没开通就是空数组。"""
    parts = _default_parts()
    parts[5] = _bits(b"")
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_no-feature", _envelope(_body(parts)))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 0
    assert _report(report)["features"] == []


def test_usage_error_exits_with_two(tmp_path):
    """题面「位置参数个数不对」：少给一个参数时退出码为 2。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_usage", _envelope(_body()))
    result = subprocess.run(
        [sys.executable, str(APP), str(envelope)],
        capture_output=True,
        text=True,
        timeout=CALL_TIMEOUT_SEC,
    )
    assert result.returncode == 2


def test_shipped_release_envelope_report_matches_expected(tmp_path):
    """题面「封套里写着序列号、机型、有效期和开通了哪些特性」：随题封套按契约出报告。"""
    report = tmp_path / "shipped.json"
    result = _run(DATA / "press_line_a.der", DATA / "vendor_pub.der", DATA / "revoked_keys.txt", report, tmp_path / "shipped.journal")
    assert result.returncode == 0
    document = _report(report)
    assert document == {
        "serial": "SN-88214",
        "device_model": "VX-300",
        "not_before": "20260101000000",
        "not_after": "20270101000000",
        "features": ["probe", "fieldbus", "calibration"],
        "authority": "Talents Instruments",
        "key_id": hashlib.sha256(_public_key_bytes()).digest()[:8].hex(),
        "sig_alg": "rsa-pkcs1-v1.5",
        "remaining_days": 214,
        "extensions": [11, 3],
    }


def test_rejects_revoked_key_identifier(tmp_path):
    """题面「又不在吊销名单里的，都不放行」：名单命中时拒收。"""
    payload = _envelope(_body())
    envelope, key, revoked, report, journal = _prepare(
        tmp_path, "envelope_revoked-key", payload, revoked_text=REVOKED_KEYS + KEY_ID.hex() + "\n"
    )
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_revocation_list_with_duplicate_lines(tmp_path):
    """题面「名单里同一行出现两次，说明这份名单本身已经坏了」：重复行时拒收。"""
    payload = _envelope(_body())
    envelope, key, revoked, report, journal = _prepare(
        tmp_path, "envelope_duplicate-list", payload, revoked_text="7c21b48f0a5d3e61\n7c21b48f0a5d3e61\n"
    )
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_revocation_list_with_malformed_line(tmp_path):
    """题面「每一行都是 16 位小写十六进制」：名单里出现大写行就拒收。"""
    payload = _envelope(_body())
    envelope, key, revoked, report, journal = _prepare(
        tmp_path, "envelope_malformed-list", payload, revoked_text="7C21B48F0A5D3E61\n"
    )
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_missing_revocation_list(tmp_path):
    """题面「名单文件缺了，说明当天的名单没同步下来」：名单缺失时拒收。"""
    payload = _envelope(_body())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_missing-list", payload)
    missing = tmp_path / "envelope_missing-list-absent.revoked"
    result = _run(envelope, key, missing, report, journal)
    assert result.returncode == 3


def test_rejects_bitmap_with_extra_zero_octet(tmp_path):
    """题面「尾部为 0 的位不进编码」：位图多带一个全零字节就拒收。"""
    parts = _default_parts()
    parts[5] = _bits(bytes([FEATURE_BITS, 0x00]))
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_extra-octet", _envelope(_body(parts)))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_bitmap_with_wrong_unused_bits(tmp_path):
    """题面「未用位数按最后一位为 1 的位置算」：未用位数少算就拒收。"""
    parts = _default_parts()
    parts[5] = _bits(bytes([0x0A]))
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_wrong-unused", _envelope(_body(parts)))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_reports_feature_name_from_second_octet(tmp_path):
    """题面「第 8 位起落到第二个字节」：两字节位图里第二个字节的位按位号报出来。"""
    parts = _default_parts()
    parts[5] = _bits(bytes([0x01, 0x08]), unused=3)
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_wide-bitmap", _envelope(_body(parts)))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 0
    assert _report(report)["features"] == ["calibration", "highspeed"]


def test_rejects_impossible_calendar_timestamp(tmp_path):
    """题面「14 位十进制的 UTC 时刻」：月份写成 13 的失效时刻拒收。"""
    parts = _default_parts()
    parts[4] = _int(20261332000000)
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_bad-calendar", _envelope(_body(parts)))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_report_counts_remaining_whole_days(tmp_path):
    """题面「按 UTC 日界算」：放行当天到失效当天的天数写进报告。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_remaining-days", _envelope(_body()))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 0
    assert _report(report)["remaining_days"] == 214


def test_rejects_envelope_with_extra_element(tmp_path):
    """题面「序列里不要再拖别的东西」：签名之后多带一个元素就拒收。"""
    payload = _envelope(_body(), extra=_octets(b"\x01\x02"))
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_extra-element", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_feature_bit_beyond_named_table(tmp_path):
    """题面「位图按命名位表的规矩编码」：位号落到第 19 位的位图拒收。"""
    parts = _default_parts()
    parts[5] = _bits(bytes([0x00, 0x00, 0x10]), unused=4)
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_wide-index", _envelope(_body(parts)))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_report_counts_zero_remaining_days_on_upper_boundary(tmp_path):
    """题面「remaining_days 是从放行时刻所在那一天到 notAfter 所在那一天的整天数」：失效当天放行记 0 天。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_zero-days", _envelope(_body()))
    result = _run(envelope, key, revoked, report, journal, stamp=str(NOT_AFTER))
    assert result.returncode == 0
    assert _report(report)["remaining_days"] == 0


def test_rejects_key_identifier_not_matching_public_key(tmp_path):
    """题面「封套里的 keyId 必须与它对上」：密钥标识与公钥指纹不符就拒收。"""
    parts = _default_parts()
    parts[7] = _octets(bytes(8))
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_foreign-keyid", _envelope(_body(parts)))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_unsorted_extension_set(tmp_path):
    """题面「集合里的项要按各自整段编码从小到大排列」且「顺序与编码大小不符的，整批拒收」：逆序就拒收。"""
    parts = _default_parts()
    parts[8] = _extensions(list(reversed(DEFAULT_EXTENSIONS)))
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_unsorted-set", _envelope(_body(parts)))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_duplicate_extension_elements(tmp_path):
    """题面「出现两项编码完全相同」：集合里有两项一模一样就拒收。"""
    parts = _default_parts()
    parts[8] = _extensions([DEFAULT_EXTENSIONS[1], DEFAULT_EXTENSIONS[1]])
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_duplicate-set", _envelope(_body(parts)))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_reports_extension_ids_in_encoded_order(tmp_path):
    """题面「按集合里的先后顺序排」：报告里的 extId 按集合顺序写出来。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_extension-order", _envelope(_body()))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 0
    assert _report(report)["extensions"] == [11, 3]


def test_accepts_pss_envelope_and_reports_scheme(tmp_path):
    """题面「PSS 那一路照 RSASSA-PSS 核」：PSS 口径的合法封套放行并写出报告。"""
    parts = _default_parts()
    body = _body(parts)
    payload = _envelope(body, signature=_pss_signature(body), algorithm=_pss_algorithm())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_pss-valid", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 0
    assert _report(report)["sig_alg"] == "rsassa-pss"


def test_reports_pkcs1_scheme_for_v15_envelope(tmp_path):
    """题面「sig_alg 按封套声明的口径写」：v1.5 口径的报告写 rsa-pkcs1-v1.5。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_scheme-report", _envelope(_body()))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 0
    assert _report(report)["sig_alg"] == "rsa-pkcs1-v1.5"


def test_rejects_unknown_signature_algorithm_oid(tmp_path):
    """题面「声明 v1.5 的只能按 v1.5 的结构核」：算法标识既不是 v1.5 也不是 PSS 就拒收。"""
    payload = _envelope(_body(), algorithm=_v15_algorithm(oid=RSA_OID))
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_unknown-oid", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_v15_algorithm_without_null_parameters(tmp_path):
    """题面「写一个 NULL」：v1.5 的算法标识参数不是 NULL 就拒收。"""
    payload = _envelope(_body(), algorithm=_v15_algorithm(params=_seq([_null()])))
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_v15-params", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_pss_parameters_missing_trailer_field(tmp_path):
    """题面「PSS 那一路的四个字段厂商一律写全，不许省成默认值」：省掉 trailerField 就拒收。"""
    body = _body()
    payload = _envelope(body, signature=_pss_signature(body), algorithm=_pss_algorithm(omit=(0xA3,)))
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_pss-omitted", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_pss_parameters_out_of_tag_order(tmp_path):
    """题面「少一个、多一个、顺序颠倒都拒收」：参数字段顺序颠倒就拒收。"""
    body = _body()
    payload = _envelope(body, signature=_pss_signature(body),
                        algorithm=_pss_algorithm(order=(0xA1, 0xA0, 0xA2, 0xA3)))
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_pss-order", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_pss_with_sha1_hash_algorithm(tmp_path):
    """题面「它自己的参数写 NULL」：PSS 的摘要算法写成 SHA-1 就拒收。"""
    body = _body()
    payload = _envelope(body, signature=_pss_signature(body), algorithm=_pss_algorithm(hash_oid=SHA1_OID))
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_pss-sha1", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_pss_mask_algorithm_with_sha1_digest(tmp_path):
    """题面「它的参数写 SHA-256 的算法标识」：MGF1 里挂 SHA-1 就拒收。"""
    body = _body()
    payload = _envelope(body, signature=_pss_signature(body),
                        algorithm=_pss_algorithm(mgf_hash_oid=SHA1_OID))
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_pss-mgf1-sha1", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_pss_mask_algorithm_with_null_parameters(tmp_path):
    """题面「它的参数写 SHA-256 的算法标识」：MGF1 的参数写成 NULL 就拒收。"""
    body = _body()
    payload = _envelope(body, signature=_pss_signature(body),
                        algorithm=_pss_algorithm(mgf_params=_null()))
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_pss-mgf1-null", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_pss_with_wrong_salt_length_parameter(tmp_path):
    """题面「盐取出来必须正好 32 个字节」：saltLength 写成 20 就拒收。"""
    body = _body()
    payload = _envelope(body, signature=_pss_signature(body), algorithm=_pss_algorithm(salt=20))
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_pss-salt-param", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_pss_with_wrong_trailer_field(tmp_path):
    """题面「厂商一律这样写」：trailerField 写成 2 就拒收。"""
    body = _body()
    payload = _envelope(body, signature=_pss_signature(body), algorithm=_pss_algorithm(trailer=2))
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_pss-trailer-param", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_pss_salt_length_with_redundant_leading_zero(tmp_path):
    """题面「整数取最短补码，非负数不许带多余的前导零字节」：saltLength 多带一个零字节就拒收。"""
    body = _body()
    payload = _envelope(body, signature=_pss_signature(body),
                        algorithm=_pss_algorithm(salt_field=_tlv(0x02, b"\x00\x20")))
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_pss-salt-padded", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_v15_signature_declared_as_pss(tmp_path):
    """题面「口径与签名结构必须对得上」：把 v1.5 的签名声明成 PSS 就拒收。"""
    body = _body()
    payload = _envelope(body, signature=_signature_for(body), algorithm=_pss_algorithm())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_cross-scheme-a", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_pss_signature_declared_as_v15(tmp_path):
    """题面「一份封套两种都不像就拒收」：把 PSS 的签名声明成 v1.5 就拒收。"""
    body = _body()
    payload = _envelope(body, signature=_pss_signature(body), algorithm=_v15_algorithm())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_cross-scheme-b", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_pss_em_with_high_bit_set(tmp_path):
    """题面「首字节的最高位必须是 0」：EM 首字节最高位为 1 就拒收。"""
    body = _body()
    payload = _envelope(body, signature=_pss_signature(body, clear_top=False),
                        algorithm=_pss_algorithm())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_pss-high-bit", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_pss_em_with_wrong_trailer_byte(tmp_path):
    """题面「末尾一个字节固定是」：EM 末尾字节不是 BC 就拒收。"""
    body = _body()
    payload = _envelope(body, signature=_pss_signature(body, trailer=0xBD), algorithm=_pss_algorithm())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_pss-trailer-byte", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_pss_em_with_short_salt(tmp_path):
    """题面「盐取出来必须正好 32 个字节」：EM 里只有 20 字节盐就拒收。"""
    body = _body()
    payload = _envelope(body, signature=_pss_signature(body, salt_length=20), algorithm=_pss_algorithm())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_pss-short-salt", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_pss_em_with_wrong_delimiter(tmp_path):
    """题面「掩码反解出来的中间串必须是一串」：定界字节不是 01 就拒收。"""
    body = _body()
    payload = _envelope(body, signature=_pss_signature(body, delimiter=0x02), algorithm=_pss_algorithm())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_pss-delimiter", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_pss_em_with_mismatched_hash(tmp_path):
    """题面「盐接在正文摘要后面再哈希一次」：摘要与盐对不上就拒收。"""
    body = _body()
    payload = _envelope(body, signature=_pss_signature(body, hash_salt=b"\x33" * PSS_SALT_LENGTH),
                        algorithm=_pss_algorithm())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_pss-hash-mismatch", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_pss_em_masked_with_sha1(tmp_path):
    """题面「掩码用 MGF1 以同一个 SHA-256 展开」：掩码用 SHA-1 生成就拒收。"""
    body = _body()
    payload = _envelope(body, signature=_pss_signature(body, mgf_hash_oid=SHA1_OID),
                        algorithm=_pss_algorithm())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_pss-mask-sha1", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_pss_signature_with_unused_bits(tmp_path):
    """题面「签名位串的开头一个字节是未用位数，它的未用位数是零」：PSS 位串未用位写成 1 就拒收。"""
    body = _body()
    payload = _envelope(body, signature=_pss_signature(body), algorithm=_pss_algorithm(),
                        signature_unused=1)
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_pss-unused-bits", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_accepts_shipped_pss_envelope_from_data_dir(tmp_path):
    """题面「签名块里的口径厂商前后发过两种，工位两种都得认」：随题的 PSS 封套也放行并按口径写报告。"""
    report = tmp_path / "shipped-pss.json"
    result = _run(DATA / "press_line_d.der", DATA / "vendor_pub.der", DATA / "revoked_keys.txt", report, tmp_path / "shipped-pss.journal")
    assert result.returncode == 0
    document = _report(report)
    assert document["sig_alg"] == "rsassa-pss"
    assert document["serial"] == "SN-88214"


def _journal_lines(path):
    return path.read_text(encoding="utf-8").splitlines()


def _journal_records(path):
    return [json.loads(line) for line in _journal_lines(path)]


def _record_for(payload, result, reason=""):
    return {
        "at": RELEASE_STAMP,
        "envelope_sha256": hashlib.sha256(payload).hexdigest(),
        "result": result,
        "reason": reason,
    }


def test_journal_appends_release_record(tmp_path):
    """题面「就是这一次核验用的那个放行时刻」「是封套文件原始字节的 SHA-256，小写十六进制」：放行时流水写一条。"""
    payload = _envelope(_body())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_journal-release", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 0
    assert _journal_records(journal) == [_record_for(payload, "released")]


def test_journal_line_is_compact_and_ordered(tmp_path):
    """题面「紧凑 JSON，分隔符后面不加空格，行尾换行」：流水那一行按字段顺序紧凑写出。"""
    payload = _envelope(_body())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_journal-compact", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 0
    raw = journal.read_text(encoding="utf-8")
    assert raw.startswith('{"at":"' + RELEASE_STAMP + '","envelope_sha256":"')
    assert raw.endswith('\n')
    assert raw.count("\n") == 1


def test_journal_records_rejection_reason(tmp_path):
    """题面「不放行时写与工位打印的那一行里冒号后面完全相同的那句话」：拒收时流水与打印一致。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_journal-rejected", _envelope(_body()))
    result = _run(envelope, key, revoked, report, journal, model="HX-900")
    assert result.returncode == 3
    records = _journal_records(journal)
    assert records[0]["result"] == "rejected"
    assert result.stderr.strip() == "封套不放行: " + records[0]["reason"]


def test_journal_created_on_rejection(tmp_path):
    """题面「不管这一次放行还是不放行，都要往流水里记一笔」：拒收时报告不写、流水要建出来。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_journal-rejected-new", _envelope(_body()))
    result = _run(envelope, key, revoked, report, journal, stamp="20251231000000")
    assert result.returncode == 3
    assert not report.exists()
    assert _journal_records(journal)[0]["result"] == "rejected"


def test_journal_keeps_single_release_record_on_rerun(tmp_path):
    """题面「上位机同一天重发一次同样的封套，第二次不再往流水里添同样的记录」：重跑不追加。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_journal-rerun", _envelope(_body()))
    first = _run(envelope, key, revoked, report, journal)
    assert first.returncode == 0
    before = journal.read_bytes()
    second = _run(envelope, key, revoked, report, journal)
    assert second.returncode == 0
    assert journal.read_bytes() == before
    assert len(_journal_records(journal)) == 1


def test_journal_keeps_single_rejection_record_on_rerun(tmp_path):
    """题面「同一份封套、同一个结果，在同一本流水里只记一条」：同样被拒的第二次不再记。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_journal-rerun-rejected", _envelope(_body()))
    first = _run(envelope, key, revoked, report, journal, model="HX-900")
    assert first.returncode == 3
    before = journal.read_bytes()
    second = _run(envelope, key, revoked, report, journal, model="HX-900")
    assert second.returncode == 3
    assert journal.read_bytes() == before


def test_journal_records_rejection_then_release(tmp_path):
    """题面「两次结果不同，两条都要记」：先被拒后来放行，流水里两条都在。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_journal-both", _envelope(_body()))
    rejected = _run(envelope, key, revoked, report, journal, model="HX-900")
    assert rejected.returncode == 3
    released = _run(envelope, key, revoked, report, journal)
    assert released.returncode == 0
    results = [record["result"] for record in _journal_records(journal)]
    assert results == ["rejected", "released"]


def test_journal_accepts_records_from_the_same_day(tmp_path):
    """题面「一本流水里只能有同一天的记录」：同一天里另一份封套的记录可以继续往后追加。"""
    payload = _envelope(_body())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_journal-same-day", payload)
    other = _envelope(_body([_int(1), _utf8("SN-88215"), _utf8("VX-300"), _int(NOT_BEFORE), _int(NOT_AFTER),
                             _bits(bytes([FEATURE_BITS])), _utf8("Talents Instruments"), _octets(KEY_ID),
                             _extensions(DEFAULT_EXTENSIONS)]))
    journal.write_text(json.dumps(_record_for(other, "released"), ensure_ascii=False, separators=(",", ":")) + "\n",
                       encoding="utf-8")
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 0
    assert len(_journal_records(journal)) == 2


def test_journal_rejects_records_from_another_day(tmp_path):
    """题面「里面已经躺着别的日期的记录，说明这本本子拿错了」：拿错本子时拒收且不动它。"""
    payload = _envelope(_body())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_journal-wrong-day", payload)
    stale = _record_for(payload, "released")
    stale["at"] = "20260101000000"
    journal.write_text(json.dumps(stale, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    before = journal.read_bytes()
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3
    assert journal.read_bytes() == before
    assert not report.exists()


def test_journal_rejects_malformed_line(tmp_path):
    """题面「流水里出现不符合上面形状的行（空行也算），同样按拿错本子处理」：坏行时拒收且不动流水。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_journal-malformed", _envelope(_body()))
    journal.write_text('{"at":"20260601120000"}\n', encoding="utf-8")
    before = journal.read_bytes()
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3
    assert journal.read_bytes() == before


def test_journal_keeps_earlier_bytes_when_appending(tmp_path):
    """题面「任何情况下都不许改动流水文件里已经写下的字节」：追加时旧字节逐字不变。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_journal-append", _envelope(_body()))
    first = _run(envelope, key, revoked, report, journal)
    assert first.returncode == 0
    before = journal.read_bytes()
    other_payload = _envelope(_body([_int(1), _utf8("SN-88216"), _utf8("VX-300"), _int(NOT_BEFORE), _int(NOT_AFTER),
                                     _bits(bytes([FEATURE_BITS])), _utf8("Talents Instruments"), _octets(KEY_ID),
                                     _extensions(DEFAULT_EXTENSIONS)]))
    other, key2, revoked2, report2, _ = _prepare(tmp_path, "envelope_journal-second", other_payload)
    second = _run(other, key2, revoked2, report2, journal)
    assert second.returncode == 0
    assert journal.read_bytes().startswith(before)
    assert len(_journal_records(journal)) == 2


def test_journal_ignored_on_usage_error(tmp_path):
    """题面「只有位置参数个数不对那一次（退出码」「和根本拿不到放行时刻的那一次不必记」：用法错误不建流水。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_journal-usage", _envelope(_body()))
    result = subprocess.run(
        [sys.executable, str(APP), str(envelope)],
        capture_output=True,
        text=True,
        timeout=CALL_TIMEOUT_SEC,
    )
    assert result.returncode == 2
    assert not journal.exists()


def test_journal_ignored_without_release_stamp(tmp_path):
    """题面「和根本拿不到放行时刻的那一次不必记」：环境变量缺失时不写流水。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_journal-no-stamp", _envelope(_body()))
    result = _run_without_environment(envelope, key, revoked, report, journal)
    assert result.returncode == 3
    assert not journal.exists()

def _public_key_with_algorithm(algorithm):
    inner = _seq([_int(MODULUS), _int(EXPONENT)])
    return _seq([algorithm, _bits(inner)])


def _run_without_model(envelope, key, revoked, report, journal):
    env = {name: value for name, value in os.environ.items()
           if name != "RELEASE_MODEL" and not name.startswith("PYTEST")}
    env["RELEASE_STAMP"] = RELEASE_STAMP
    return subprocess.run(
        [sys.executable, str(APP), str(envelope), str(key), str(revoked), str(report), str(journal)],
        capture_output=True,
        text=True,
        timeout=CALL_TIMEOUT_SEC,
        env=env,
    )


def test_rejects_public_key_with_foreign_algorithm_oid(tmp_path):
    """题面「这一段里的 OID 必须就是 RSA 那一串」：公钥算法标识换成别的 OID 就拒收。"""
    key_payload = _public_key_with_algorithm(_seq([_tlv(0x06, SHA1_OID), _tlv(0x05, b"")]))
    parts = _default_parts()
    parts[7] = _octets(hashlib.sha256(key_payload).digest()[:8])
    envelope, key, revoked, report, journal = _prepare(
        tmp_path, "envelope_foreign-pubkey-oid", _envelope(_body(parts)), key_payload=key_payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_public_key_with_padded_null_parameter(tmp_path):
    """题面「后面的 NULL 里不许夹带任何字节」：公钥算法标识的 NULL 里塞了字节就拒收。"""
    key_payload = _public_key_with_algorithm(_seq([_tlv(0x06, RSA_OID), _tlv(0x05, b"\x00")]))
    parts = _default_parts()
    parts[7] = _octets(hashlib.sha256(key_payload).digest()[:8])
    envelope, key, revoked, report, journal = _prepare(
        tmp_path, "envelope_padded-pubkey-null", _envelope(_body(parts)), key_payload=key_payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_feature_bitmap_with_nonzero_unused_bits(tmp_path):
    """题面「最后一个字节里被声明为未用的那些低位必须都是零」：位图未用低位非零就拒收。"""
    parts = _default_parts()
    parts[5] = _bits(b"\x0b", unused=3)
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_bitmap-unused-bits", _envelope(_body(parts)))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_journal_with_blank_line(tmp_path):
    """题面「流水里出现不符合上面形状的行（空行也算）」：流水里多一条空行就按拿错本子拒收。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_journal-blank-line", _envelope(_body()))
    first = _run(envelope, key, revoked, report, journal)
    assert first.returncode == 0
    journal.write_bytes(journal.read_bytes() + b"\n")
    before = journal.read_bytes()
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3
    assert journal.read_bytes() == before


def test_journals_rejection_when_only_release_model_is_missing(tmp_path):
    """题面「只有位置参数个数不对那一次（退出码」「和根本拿不到放行时刻的那一次不必记」：只缺机型的拒收要记账。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_journal-no-model", _envelope(_body()))
    result = _run_without_model(envelope, key, revoked, report, journal)
    records = _journal_records(journal)
    assert result.returncode == 3
    assert records[0]["result"] == "rejected"
    assert result.stderr.strip() == "封套不放行: " + records[0]["reason"]


def test_rejection_leaves_no_new_report_for_structure_failure(tmp_path):
    """题面「被拒或参数不对的时候报告不写」：结构类拒收同样不新建报告。"""
    envelope, key, revoked, report, journal = _prepare(
        tmp_path, "envelope_no-report-structure", _envelope(_body(), outer=_tlv_padded_length))
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3
    assert not report.exists()


def test_report_is_compact_json_with_trailing_newline(tmp_path):
    """题面「紧凑 JSON，分隔符后面不加空格，结尾换一行」：报告按原始字节核格式。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_report-bytes", _envelope(_body()))
    result = _run(envelope, key, revoked, report, journal)
    raw = report.read_bytes()
    assert result.returncode == 0
    assert b": " not in raw and b", " not in raw
    assert raw.count(b"\n") == 1 and raw.endswith(b"\n")


def test_rejects_revoked_list_with_blank_line(tmp_path):
    """题面「格式对不上的行也一样」：名单里夹一条空行就按名单坏掉处理。"""
    envelope, key, revoked, report, journal = _prepare(
        tmp_path, "envelope_revoked-blank", _envelope(_body()))
    revoked.write_text("7c21b48f0a5d3e61\n\n", encoding="utf-8")
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_revoked_list_line_with_surrounding_space(tmp_path):
    """题面「每一行都是 16 位小写十六进制」：行首尾多出空白就不算合规的一行。"""
    envelope, key, revoked, report, journal = _prepare(
        tmp_path, "envelope_revoked-space", _envelope(_body()))
    revoked.write_text(" 7c21b48f0a5d3e61\n", encoding="utf-8")
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3


def test_rejects_impossible_calendar_release_stamp(tmp_path):
    """题面「`RELEASE_STAMP` 是 14 位十进制的 UTC 时刻」：月份写成 13 的放行时刻按拿不到处理。"""
    envelope, key, revoked, report, journal = _prepare(
        tmp_path, "envelope_bad-release-stamp", _envelope(_body()))
    result = _run(envelope, key, revoked, report, journal, stamp="20261301120000")
    assert result.returncode == 3
    assert not report.exists()



def _summary_path(journal):
    return journal.parent / (journal.name + ".summary")


def _posted_summary(journal):
    return json.loads(_summary_path(journal).read_text(encoding="utf-8"))


def _envelope_with(serial, not_before=NOT_BEFORE, not_after=NOT_AFTER):
    parts = _default_parts()
    parts[1] = _utf8(serial)
    parts[3] = _int(not_before)
    parts[4] = _int(not_after)
    return _envelope(_body(parts))


def test_summary_is_posted_next_to_the_journal(tmp_path):
    """题面「小结贴在流水本子旁边：流水文件的路径后面再接 `.summary` 就是小结的路径」：小结与流水同名同目录。"""
    payload = _envelope(_body())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_summary-post", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 0
    assert _summary_path(journal).is_file()


def test_summary_line_is_compact_and_ordered(tmp_path):
    """题面「小结是一份紧凑 JSON，分隔符后面不加空格，结尾换行」：小结按紧凑格式写出。"""
    payload = _envelope(_body())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_summary-compact", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 0
    raw = _summary_path(journal).read_text(encoding="utf-8")
    ordered = {"day": "20260601", "released": 1, "rejected": 0, "reasons": {}}
    expected = json.dumps(ordered, ensure_ascii=False, separators=(",", ":")) + "\n"
    assert raw == expected


def test_summary_fields_follow_contract_order(tmp_path):
    """题面「字段按 `day`、`released`、`rejected`、`reasons` 的顺序排」：小结的字段顺序固定。"""
    payload = _envelope(_body())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_summary-order", payload)
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 0
    raw = _summary_path(journal).read_text(encoding="utf-8")
    assert list(json.loads(raw)) == ["day", "released", "rejected", "reasons"]


def test_summary_day_comes_from_journal_record(tmp_path):
    """题面「`day` 是这本流水的日期，取流水里记录的 `at` 的前 8 位」：换个放行时刻，day 跟着流水走。"""
    payload = _envelope(_body())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_summary-day", payload)
    result = _run(envelope, key, revoked, report, journal, stamp="20260610100000")
    assert result.returncode == 0
    assert _posted_summary(journal)["day"] == "20260610"


def test_summary_matches_empty_journal_projection(tmp_path):
    """题面「流水一条记录也没有时写空字符串」：空流水算出的小结就是空日期那一份。"""
    payload = _envelope(_body())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_summary-empty", payload)
    journal.write_text("", encoding="utf-8")
    _summary_path(journal).write_text('{"day":"","released":0,"rejected":0,"reasons":{}}\n', encoding="utf-8")
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 0
    assert _posted_summary(journal)["released"] == 1


def test_summary_counts_net_release_after_rejection(tmp_path):
    """题面「同一份封套按它最后一次的结果算一台，先被拒、后来改好又放行的那一份只算放行」：净台数只算最后一次。"""
    payload = _envelope(_body())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_summary-net", payload)
    rejected = _run(envelope, key, revoked, report, journal, model="HX-900")
    assert rejected.returncode == 3
    released = _run(envelope, key, revoked, report, journal)
    assert released.returncode == 0
    posted = _posted_summary(journal)
    assert posted["released"] == 1
    assert posted["rejected"] == 0


def test_summary_removes_reason_that_netted_to_zero(tmp_path):
    """题面「净剩为零的原因不写进来」：被翻案的那次拒收不再挂在原因台账上。"""
    payload = _envelope(_body())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_summary-zero", payload)
    rejected = _run(envelope, key, revoked, report, journal, model="HX-900")
    assert rejected.returncode == 3
    released = _run(envelope, key, revoked, report, journal)
    assert released.returncode == 0
    assert _posted_summary(journal)["reasons"] == {}


def test_summary_reason_tally_counts_repeated_reason(tmp_path):
    """题面「`reasons` 是当班净拒收的原因台账，键是不放行时写进流水的那句原因原文，值是它净剩的台数。」：同一个原因拒收多次要累计。"""
    first_payload = _envelope_with("SN-41001")
    first, key, revoked, report, journal = _prepare(tmp_path, "envelope_summary-tally-a", first_payload)
    one = _run(first, key, revoked, report, journal, model="HX-900")
    assert one.returncode == 3
    second_payload = _envelope_with("SN-41002")
    second, key2, revoked2, report2, _ = _prepare(tmp_path, "envelope_summary-tally-b", second_payload)
    two = _run(second, key2, revoked2, report2, journal, model="HX-900")
    assert two.returncode == 3
    third_payload = _envelope_with("SN-41003", NOT_BEFORE, 20250930000000)
    third, key3, revoked3, report3, _ = _prepare(tmp_path, "envelope_summary-tally-c", third_payload)
    three = _run(third, key3, revoked3, report3, journal)
    assert three.returncode == 3
    posted = _posted_summary(journal)
    assert posted["reasons"]["机型与当班型号不符"] == 2
    assert posted["rejected"] == 3


def test_summary_orders_reasons_by_count_descending(tmp_path):
    """题面「键先按台数从多到少排」：拒收台数多的那一类原因排在前面。"""
    first_payload = _envelope_with("SN-41001")
    first, key, revoked, report, journal = _prepare(tmp_path, "envelope_summary-rank-a", first_payload)
    one = _run(first, key, revoked, report, journal, model="HX-900")
    assert one.returncode == 3
    second_payload = _envelope_with("SN-41002")
    second, key2, revoked2, report2, _ = _prepare(tmp_path, "envelope_summary-rank-b", second_payload)
    two = _run(second, key2, revoked2, report2, journal, model="HX-900")
    assert two.returncode == 3
    third_payload = _envelope_with("SN-41003", NOT_BEFORE, 20250930000000)
    third, key3, revoked3, report3, _ = _prepare(tmp_path, "envelope_summary-rank-c", third_payload)
    three = _run(third, key3, revoked3, report3, journal)
    assert three.returncode == 3
    posted = _posted_summary(journal)
    assert list(posted["reasons"]) == ["机型与当班型号不符", "封套不在有效期内"]


def test_summary_orders_equal_counts_by_reason_bytes(tmp_path):
    """题面「台数相同的按原因的 UTF-8 字节串从小到大排」：同样一票的原因按字节序改名次。"""
    revoked_payload = _envelope_with("SN-42001")
    revoked_env, key, revoked, report, journal = _prepare(
        tmp_path, "envelope_summary-tie-a", revoked_payload, revoked_text=REVOKED_KEYS + KEY_ID.hex() + "\n"
    )
    first = _run(revoked_env, key, revoked, report, journal)
    assert first.returncode == 3
    expired_payload = _envelope_with("SN-42002", NOT_BEFORE, 20250930000000)
    expired_env, key2, revoked2, report2, _ = _prepare(tmp_path, "envelope_summary-tie-b", expired_payload)
    second = _run(expired_env, key2, revoked2, report2, journal)
    assert second.returncode == 3
    assert list(_posted_summary(journal)["reasons"]) == ["封套不在有效期内", "签发密钥已在吊销名单里"]


def test_summary_is_stable_on_rerun(tmp_path):
    """题面「算出来的内容必须跟小结文件里的字节一模一样」：同一份封套再核一次，小结逐字节不变。"""
    payload = _envelope(_body())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_summary-rerun", payload)
    first = _run(envelope, key, revoked, report, journal)
    assert first.returncode == 0
    before = _summary_path(journal).read_bytes()
    second = _run(envelope, key, revoked, report, journal)
    assert second.returncode == 0
    assert _summary_path(journal).read_bytes() == before


def test_summary_mismatch_rejects_and_leaves_everything_untouched(tmp_path):
    """题面「对不上，就当小结贴错了，这一次直接不放行，报告不写，流水和小结都不许动」：小结被改过就停线。"""
    payload = _envelope(_body())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_summary-stale", payload)
    first = _run(envelope, key, revoked, report, journal)
    assert first.returncode == 0
    journal_before = journal.read_bytes()
    report.unlink()
    _summary_path(journal).write_text('{"day":"20260601","released":7,"rejected":0,"reasons":{}}\n', encoding="utf-8")
    summary_before = _summary_path(journal).read_bytes()
    second = _run(envelope, key, revoked, report, journal)
    assert second.returncode == 3
    assert journal.read_bytes() == journal_before
    assert _summary_path(journal).read_bytes() == summary_before
    assert not report.exists()


def test_summary_with_same_meaning_but_other_bytes_rejects(tmp_path):
    """题面「算出来的内容必须跟小结文件里的字节一模一样」：意思一样但字节不同也算贴错。"""
    payload = _envelope(_body())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_summary-bytes", payload)
    first = _run(envelope, key, revoked, report, journal)
    assert first.returncode == 0
    spaced = '{"day": "20260601", "released": 1, "rejected": 0, "reasons": {}}\n'
    _summary_path(journal).write_text(spaced, encoding="utf-8")
    second = _run(envelope, key, revoked, report, journal)
    assert second.returncode == 3
    assert _summary_path(journal).read_text(encoding="utf-8") == spaced


def test_summary_missing_is_treated_as_unposted(tmp_path):
    """题面「小结文件不在就按没贴处理，本次核验完了再把它贴上去」：没贴小结时照常核验并补上。"""
    payload = _envelope(_body())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_summary-missing", payload)
    seeded = _envelope_with("SN-43001")
    journal.write_text(json.dumps(_record_for(seeded, "released"), ensure_ascii=False, separators=(",", ":")) + "\n",
                       encoding="utf-8")
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 0
    assert _posted_summary(journal)["released"] == 2


def test_summary_ignored_on_usage_error(tmp_path):
    """题面「退出码 `2` 的那一次和拿不到放行时刻的那一次不贴」：参数个数不对时不贴小结。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_summary-usage", _envelope(_body()))
    result = subprocess.run(
        [sys.executable, str(APP), str(envelope)],
        capture_output=True,
        text=True,
        timeout=CALL_TIMEOUT_SEC,
    )
    assert result.returncode == 2
    assert not _summary_path(journal).exists()


def test_summary_ignored_without_release_stamp(tmp_path):
    """题面「拿不到放行时刻的那一次不贴」：环境变量缺失时不贴小结。"""
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_summary-no-stamp", _envelope(_body()))
    result = _run_without_environment(envelope, key, revoked, report, journal)
    assert result.returncode == 3
    assert not _summary_path(journal).exists()


def test_summary_untouched_when_journal_has_another_day(tmp_path):
    """题面「这一次因为流水本子本身有问题而没记账的，小结也不动」：拿错本子时不贴小结。"""
    payload = _envelope(_body())
    envelope, key, revoked, report, journal = _prepare(tmp_path, "envelope_summary-wrong-day", payload)
    stale = _record_for(payload, "released")
    stale["at"] = "20260101000000"
    journal.write_text(json.dumps(stale, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    result = _run(envelope, key, revoked, report, journal)
    assert result.returncode == 3
    assert not _summary_path(journal).exists()
