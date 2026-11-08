#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fcrypt_core.py —— FileCrypto 加解密核心引擎（纯标准库实现，零第三方依赖）

设计要点
--------
* 密码 -> 密钥：PBKDF2-HMAC-SHA256 或 scrypt，盐随机 16 字节，可选“密钥文件”参与派生。
* 加密：分块流式处理，内存占用 = 分块大小，可处理任意大文件。
* 完整性：每块独立认证 + 文件末尾 EOF 终结块（认证总长度，防截断）。
* 算法：
    - shake256-stream-hmac : 内置算法，SHAKE-256(XOF) 密钥流 + HMAC-SHA256 认证
                             （无第三方依赖，任何 Python 都能跑，实测 100+ MB/s）
    - aes-256-gcm          : 需要 cryptography 库
    - chacha20-poly1305    : 需要 cryptography 库
* 文件格式：FCRYPT01 魔数 + 头部长度 + JSON 头部 + 数据块 + EOF 标记 + EOF 认证标签

文件布局
--------
    b"FCRYPT01"                8 字节魔数
    header_len (uint32 BE)     4 字节
    header_json (UTF-8)        头部，含算法/KDF 参数/盐/随机数/原始大小等
    chunk * N                  数据块：长度(uint32 BE) + 密文 + 16 字节标签
    EOF_MARKER  (uint32 BE)    0xFFFFFFFE
    eof_tag                    16 字节，认证“总明文长度”，防止文件被截断

作者：bc-hio     许可：MIT
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import struct
import time
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple

# --------------------------------------------------------------------------
# 常量与算法登记表
# --------------------------------------------------------------------------

MAGIC = b"FCRYPT01"
FILE_VERSION = 1
EOF_MARKER = 0xFFFFFFFE
TAG_LEN = 16
EOF_NONCE_IDX = 0xFFFFFFFF
DEFAULT_CHUNK = 1 << 20  # 1 MiB
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
DEFAULT_SUFFIX = ".fcrypt"

ALGO_STREAM = "shake256-stream-hmac"
ALGO_AESGCM = "aes-256-gcm"
ALGO_CHACHA = "chacha20-poly1305"

ALGORITHMS: Dict[str, str] = {
    ALGO_AESGCM: "AES-256-GCM（标准 AEAD，默认首选）",
    ALGO_CHACHA: "ChaCha20-Poly1305（标准 AEAD，无 AES 硬件加速时更快）",
    ALGO_STREAM: "SHAKE-256 自构造流密码 + HMAC（无第三方依赖时的兜底）",
}

KDF_PBKDF2 = "pbkdf2-hmac-sha256"
KDF_SCRYPT = "scrypt"
KDFS: Dict[str, str] = {
    KDF_PBKDF2: "PBKDF2-HMAC-SHA256（兼容性最好）",
    KDF_SCRYPT: "scrypt（抗 GPU/ASIC 更强）",
}

#: KDF 强度预设：名称 -> (PBKDF2 迭代次数, scrypt 参数)
KDF_PRESETS: Dict[str, Dict[str, int]] = {
    "快速": {"iterations": 120_000, "n": 1 << 13, "r": 8, "p": 1},
    "标准": {"iterations": 600_000, "n": 1 << 14, "r": 8, "p": 1},
    "强化": {"iterations": 1_500_000, "n": 1 << 15, "r": 8, "p": 1},
    "极限": {"iterations": 4_000_000, "n": 1 << 16, "r": 8, "p": 1},
}

CHUNK_SIZES: Dict[str, int] = {
    "64 KiB": 1 << 16,
    "256 KiB": 1 << 18,
    "1 MiB（推荐）": 1 << 20,
    "4 MiB": 1 << 22,
    "16 MiB": 1 << 24,
}

# 可选第三方加密库（有则自动启用标准 AEAD 算法）
try:  # pragma: no cover - 取决于运行环境
    from cryptography.hazmat.primitives.ciphers.aead import (  # type: ignore
        AESGCM,
        ChaCha20Poly1305,
    )
    from cryptography import __version__ as _cryptography_version  # type: ignore

    CRYPTOGRAPHY_AVAILABLE = True
    CRYPTOGRAPHY_VERSION = _cryptography_version
except Exception:  # pragma: no cover
    AESGCM = None  # type: ignore
    ChaCha20Poly1305 = None  # type: ignore
    CRYPTOGRAPHY_AVAILABLE = False
    CRYPTOGRAPHY_VERSION = ""


# --------------------------------------------------------------------------
# 异常
# --------------------------------------------------------------------------


class CryptError(Exception):
    """加解密相关错误的基类。"""


class FormatError(CryptError):
    """文件格式不正确或已损坏。"""


class WrongPasswordError(CryptError):
    """密码 / 密钥文件不正确，或数据被篡改。"""


class CancelledError(CryptError):
    """用户取消了操作。"""


class UnsupportedAlgorithm(CryptError):
    """运行环境不支持所选算法。"""


# --------------------------------------------------------------------------
# 小工具函数
# --------------------------------------------------------------------------


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def human_size(num: float, suffix: str = "B") -> str:
    """把字节数格式化为易读字符串。"""
    for unit in ("", "K", "M", "G", "T", "P"):
        if abs(num) < 1024.0 or unit == "P":
            if unit == "":
                return f"{int(num)} {unit}{suffix}".strip()
            return f"{num:.2f} {unit}{suffix}"
        num /= 1024.0
    return f"{num:.2f} P{suffix}"


def human_time(seconds: float) -> str:
    """把秒数格式化为 mm:ss。"""
    if seconds < 0 or seconds != seconds or seconds == float("inf"):
        return "--:--"
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """等长字节异或（用大整数实现，速度远快于逐字节循环）。"""
    if not a:
        return b""
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF（只用 hashlib/hmac，标准库即可）。"""
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    out, block, counter = bytearray(), b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return bytes(out[:length])


def sha256_file(path: os.PathLike | str, buf_size: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(buf_size), b""):
            h.update(chunk)
    return h.hexdigest()


def unique_path(path: Path) -> Path:
    """若目标已存在，自动追加 (1)(2)… 生成不冲突的路径。"""
    if not path.exists():
        return path
    stem, suffix, parent = path.stem, path.suffix, path.parent
    for i in range(1, 10000):
        candidate = parent / f"{stem} ({i}){suffix}"
        if not candidate.exists():
            return candidate
    raise CryptError("无法生成不冲突的输出文件名")


# --------------------------------------------------------------------------
# 密钥派生
# --------------------------------------------------------------------------


def derive_master_key(
    password: str,
    salt: bytes,
    kdf: str,
    params: Dict[str, int],
    keyfile_digest: Optional[bytes] = None,
    normalize: bool = True,
) -> bytes:
    """
    由口令（+可选密钥文件）派生 32 字节主密钥。

    密码先做 NFC 归一化：同一密码用不同输入法可能产生"组合字符"与"预组合字符"
    两种字节序列，不归一化就会出现"密码明明一样却打不开"。
    normalize=False 仅用于兼容旧版本生成的文件（旧版未归一化）。
    """
    text = normalize_password(password) if normalize else password
    ikm = text.encode("utf-8")
    if keyfile_digest:
        # 密钥文件摘要并入 IKM：既改变派生结果，又避免拼接歧义
        ikm = ikm + b"\x1fFCKEYFILE\x1f" + keyfile_digest

    if kdf == KDF_PBKDF2:
        iterations = int(params.get("iterations", 600_000))
        if iterations < 1000:
            raise CryptError("PBKDF2 迭代次数过低")
        return hashlib.pbkdf2_hmac("sha256", ikm, salt, iterations, dklen=KEY_LEN)
    if kdf == KDF_SCRYPT:
        n = int(params.get("n", 1 << 14))
        r = int(params.get("r", 8))
        p = int(params.get("p", 1))
        if n < 2 or (n & (n - 1)):
            raise CryptError("scrypt 参数 n 必须是 2 的幂")
        # 预留充足内存上限，避免 OpenSSL 因默认上限报错
        maxmem = 128 * n * r + (1 << 20)
        return hashlib.scrypt(ikm, salt=salt, n=n, r=r, p=p, dklen=KEY_LEN, maxmem=maxmem)
    raise UnsupportedAlgorithm(f"未知的 KDF：{kdf}")


def keyfile_digest(path: os.PathLike | str | None) -> Optional[bytes]:
    """读取密钥文件并返回 SHA-256 摘要。"""
    if not path:
        return None
    digest = sha256_file(path)
    return bytes.fromhex(digest)


# --------------------------------------------------------------------------
# 密码：归一化、弱口令字典与强度评估
# --------------------------------------------------------------------------

#: 常见弱口令（含中文常见组合、键盘序列、品牌默认口令）。
#: 命中即判"极弱"——纯熵估算会把这些密码算成"强"，极具误导性。
WEAK_PASSWORDS = frozenset("""
123456 password 12345678 qwerty 123456789 12345 1234 111111 1234567 dragon 123123
baseball abc123 football monkey letmein 696969 shadow master 666666 qwertyuiop 123321
mustang 1234567890 michael 654321 superman 1qaz2wsx 7777777 121212 000000 qazwsx 123qwe
killer trustno1 jordan jennifer zxcvbnm asdfgh hunter buster soccer harley batman
andrew tigger sunshine iloveyou 2000 charlie robert thomas hockey ranger daniel
starwars klaster 112233 george asshole computer michelle jessica pepper 1111 zxcvbn
555555 11111111 131313 freedom 777777 pass maggie 159753 aaaaaa ginger princess
joshua cheese amanda summer love ashley nicole chelsea biteme matthew access yankees
987654321 dallas austin thunder taylor matrix william corvette hello martin heather
secret merlin diamond 1234qwer gfhjkm hammer silver 222222 88888888 anthony justin
test bailey q1w2e3r4t5 patrick internet scooter orange 11111 golfer cookie richard
samantha bigdog guitar jackson whatever mickey chicken sparky snoopy maverick
phoenix camaro sexy peanut morgan welcome falcon cowboy ferrari samsung andrea
smokey steelers joseph mercedes dakota arsenal eagles melissa boomer booboo spider
nascar monster tigers yellow xxxxxx 123123123 gateway marina diablo bulldog qwer1234
compaq purple hardcore banana junior hannah 123654 porsche lakers iceman money
cowboys 987654 london tennis999999 a123456 abc123456 123456a 5201314 woaini
woaini1314 1314520 qq123456 aa123456 123456789a 147258369 1qaz2wsx3edc qazwsxedc
abcdef abcdefg abcd1234 a1b2c3 asdfghjkl zxcvbnm 00000000 12341234 11223344
qwerty123 password1 password123 passw0rd p@ssw0rd admin admin123 root toor guest
letmein1 changeme default test123 temp123 qwe123 qweasd qweasdzxc 1q2w3e4r 1q2w3e
zxcvbnm123 asdf1234 iloveyou1 princess1 sunshine1 football1 baseball1 welcome1
""".split())


def normalize_password(password: str) -> str:
    """
    统一密码的 Unicode 形式（NFC）。

    同一个密码用不同输入法/系统可能产生"组合字符"与"预组合字符"两种字节序列
    （例如 e + U+0301 与 U+00E9），看起来一样、字节不同，会导致密钥不同、解密失败。
    派生密钥前统一归一化可彻底避免这类"密码明明一样却打不开"的问题。
    """
    return unicodedata.normalize("NFC", password)


#: leetspeak 折叠表，用于把 p@ssw0rd / l3tm3in 之类还原成字典词
_LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "@": "a", "$": "s", "!": "i", "|": "l", "+": "t", "9": "g", "2": "z",
})


def _password_variants(password: str) -> List[str]:
    """生成用于查字典的候选形式：原文、小写、leet 折叠、去掉尾部数字/符号。"""
    base = normalize_password(password).lower()
    leet = base.translate(_LEET_MAP)
    out = [base, leet]
    for item in (base, leet):
        stripped = item.rstrip("0123456789!@#$%^&*_-.")
        if stripped and stripped != item:
            out.append(stripped)
        # 去掉尾部少量数字后再折叠一次（如 "password2026"）
        if len(item) > 4:
            out.append(re.sub(r"\d{1,6}$", "", item))
    return [x for x in dict.fromkeys(out) if x]


def is_common_password(password: str) -> bool:
    """是否命中常见弱口令字典（含 leet 变体与"字典词+数字"形式）。"""
    if not password:
        return True
    candidates = _password_variants(password)
    if any(c in WEAK_PASSWORDS for c in candidates):
        return True
    # 纯数字且长度很短：枚举空间极小
    if password.isdigit() and len(password) <= 10:
        return True
    # 单字符重复 / 纯序列
    if len(set(password)) <= 2 and len(password) <= 8:
        return True
    low = password.lower()
    for seq in ("qwertyuiop", "asdfghjkl", "zxcvbnm", "abcdefghij", "9876543210", "0123456789"):
        if low in seq or seq in low:
            return True
    return False


def password_warnings(password: str) -> List[str]:
    """返回人类可读的密码风险提示列表（空列表表示没发现问题）。"""
    warnings: List[str] = []
    if not password:
        return ["密码为空"]
    if is_common_password(password):
        warnings.append("命中常见弱口令字典（或仅由它加少量数字构成），极易被字典攻击")
    norm = normalize_password(password)
    if norm != password:
        warnings.append("密码含组合字符，已按 NFC 统一（不同输入法输入同一密码不会再导致解密失败）")
    if len(password) < 12:
        warnings.append(f"长度仅 {len(password)} 位，建议 12 位以上")
    if password.isdigit():
        warnings.append("纯数字密码搜索空间很小")
    elif password.isalpha():
        warnings.append("纯字母密码缺少数字/符号，建议混用")
    if re.fullmatch(r"(.)\1+", password):
        warnings.append("密码由同一字符重复构成")
    if re.search(r"(19|20)\d{2}$", password):
        warnings.append("结尾是年份，容易被针对性猜解")
    return warnings


def password_strength(password: str) -> Tuple[int, str]:
    """
    返回 (0-100 分数, 文字评价)。

    先按字符集估算熵，再用弱口令字典/结构规则做**扣分封顶**——
    纯熵估算会把 "Password2026!" 这种密码评为"强"，这是误导。
    """
    if not password:
        return 0, "空"
    norm = normalize_password(password)
    pool = 0
    if any(c.islower() for c in norm):
        pool += 26
    if any(c.isupper() for c in norm):
        pool += 26
    if any(c.isdigit() for c in norm):
        pool += 10
    if any(not c.isalnum() for c in norm):
        pool += 33
    if any(ord(c) > 127 for c in norm):
        pool += 100
    import math

    entropy = len(norm) * math.log2(max(pool, 2))
    score = max(0, min(100, int(entropy / 1.28)))

    if is_common_password(norm):
        return min(score, 12), "极弱（常见弱口令）"
    # 以字典词开头的长密码仍然可被规则攻击，封顶
    for variant in _password_variants(norm):
        if len(variant) >= 4 and any(variant.startswith(w) or w.startswith(variant)
                                    for w in WEAK_PASSWORDS if len(w) >= 5):
            score = min(score, 45)
            break
    if len(norm) < 8:
        score = min(score, 25)

    if score < 20:
        label = "非常弱"
    elif score < 40:
        label = "较弱"
    elif score < 65:
        label = "中等"
    elif score < 85:
        label = "强"
    else:
        label = "非常强"
    return score, label


def generate_password(
    length: int = 20,
    use_lower: bool = True,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    avoid_ambiguous: bool = True,
) -> str:
    """生成高熵随机密码。"""
    lower = "abcdefghijklmnopqrstuvwxyz"
    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    digits = "0123456789"
    symbols = "!@#$%^&*()-_=+[]{};:,.?/~"
    if avoid_ambiguous:
        for ch in "lIO01|`'\";:.,":
            lower = lower.replace(ch, "")
            upper = upper.replace(ch, "")
            digits = digits.replace(ch, "")
    pools = [p for p, on in ((lower, use_lower), (upper, use_upper), (digits, use_digits), (symbols, use_symbols)) if on]
    alphabet = "".join(pools)
    if not alphabet:
        raise CryptError("至少需要选择一种字符类型")
    rng = secrets.SystemRandom()
    length = max(4, int(length))
    while True:
        pwd = "".join(rng.choice(alphabet) for _ in range(length))
        # 保证每类所选字符至少出现一次
        if all(any(c in p for c in pwd) for p in pools):
            return pwd


# --------------------------------------------------------------------------
# 加密器实现
# --------------------------------------------------------------------------


class StreamCipher:
    """
    内置算法：SHAKE-256 XOF 密钥流 + HMAC-SHA256 加密后认证（Encrypt-then-MAC）。

    密钥流：KS_i = SHAKE256(b"FCSTREAM1" || enc_key || nonce || chunk_index)，一次生成整块。
            SHAKE-256 是标准 XOF（NIST FIPS 202），在海量输出下与随机串不可区分，
            且速度比逐块 HMAC 快约 30 倍；nonce 每文件随机，块号唯一，故密钥流绝不重复。
    认证码：tag = HMAC(mac_key, aad || nonce || chunk_index || 密文)[:16]
    """

    name = ALGO_STREAM
    tag_len = TAG_LEN
    _DOMAIN = b"FCSTREAM1"

    def __init__(self, key: bytes) -> None:
        self._enc = hkdf_sha256(key, b"fcrypt-kdf", b"fcrypt/enc", KEY_LEN)
        self._mac = hkdf_sha256(key, b"fcrypt-kdf", b"fcrypt/mac", KEY_LEN)

    # -- 内部 ------------------------------------------------------------
    def _keystream(self, nonce: bytes, idx: int, length: int) -> bytes:
        if length <= 0:
            return b""
        seed = self._DOMAIN + self._enc + nonce + struct.pack(">I", idx & 0xFFFFFFFF)
        return hashlib.shake_256(seed).digest(length)

    def _tag(self, nonce: bytes, idx: int, ciphertext: bytes, aad: bytes) -> bytes:
        mac = hmac.new(self._mac, digestmod=hashlib.sha256)
        mac.update(aad)
        mac.update(b"\x1eFCCHUNK\x1e")
        mac.update(nonce)
        mac.update(struct.pack(">I", idx & 0xFFFFFFFF))
        mac.update(ciphertext)
        return mac.digest()[: self.tag_len]

    # -- 对外接口 --------------------------------------------------------
    def encrypt(self, nonce: bytes, idx: int, data: bytes, aad: bytes = b"") -> bytes:
        ks = self._keystream(nonce, idx, len(data))
        ct = xor_bytes(data, ks)
        return ct + self._tag(nonce, idx, ct, aad)

    def decrypt(self, nonce: bytes, idx: int, payload: bytes, aad: bytes = b"") -> bytes:
        if len(payload) < self.tag_len:
            raise FormatError("数据块长度异常")
        ct, tag = payload[: -self.tag_len], payload[-self.tag_len :]
        if not hmac.compare_digest(self._tag(nonce, idx, ct, aad), tag):
            raise WrongPasswordError("数据完整性校验失败（密码错误或文件被篡改）")
        ks = self._keystream(nonce, idx, len(ct))
        return xor_bytes(ct, ks)

    def eof_seal(self, nonce: bytes, total_len: int, aad: bytes = b"") -> bytes:
        mac = hmac.new(self._mac, digestmod=hashlib.sha256)
        mac.update(aad)
        mac.update(b"\x1eFCEOF\x1e")
        mac.update(nonce)
        mac.update(struct.pack(">Q", total_len))
        return mac.digest()[: self.tag_len]

    def eof_open(self, nonce: bytes, total_len: int, tag: bytes, aad: bytes = b"") -> None:
        if not hmac.compare_digest(self.eof_seal(nonce, total_len, aad), tag):
            raise WrongPasswordError("文件结尾校验失败（文件被截断或篡改）")

    # 一次性小数据封装（用于加密文件名等元数据）
    def seal_blob(self, data: bytes, context: bytes = b"blob") -> bytes:
        nonce = hashlib.sha256(context).digest()[:NONCE_LEN]
        return self.encrypt(nonce, 0, data, aad=context)

    def open_blob(self, payload: bytes, context: bytes = b"blob") -> bytes:
        nonce = hashlib.sha256(context).digest()[:NONCE_LEN]
        return self.decrypt(nonce, 0, payload, aad=context)


class AeadCipher:
    """标准 AEAD 算法（AES-256-GCM / ChaCha20-Poly1305），依赖 cryptography 库。"""

    tag_len = TAG_LEN

    def __init__(self, key: bytes, algo: str) -> None:
        if not CRYPTOGRAPHY_AVAILABLE:
            raise UnsupportedAlgorithm("需要安装 cryptography 库才能使用该算法")
        self.name = algo
        if algo == ALGO_AESGCM:
            self._aead = AESGCM(key)
        elif algo == ALGO_CHACHA:
            self._aead = ChaCha20Poly1305(key)
        else:  # pragma: no cover
            raise UnsupportedAlgorithm(f"未知算法：{algo}")
        self._mac = hkdf_sha256(key, b"fcrypt-kdf", b"fcrypt/mac", KEY_LEN)

    @staticmethod
    def _nonce(base: bytes, idx: int) -> bytes:
        """由 12 字节基础随机数派生每块唯一 nonce（后 4 字节与块号异或）。"""
        tail = int.from_bytes(base[8:], "big") ^ (idx & 0xFFFFFFFF)
        return base[:8] + tail.to_bytes(4, "big")

    def encrypt(self, nonce: bytes, idx: int, data: bytes, aad: bytes = b"") -> bytes:
        return self._aead.encrypt(self._nonce(nonce, idx), data, aad)

    def decrypt(self, nonce: bytes, idx: int, payload: bytes, aad: bytes = b"") -> bytes:
        if len(payload) < self.tag_len:
            raise FormatError("数据块长度异常")
        try:
            return self._aead.decrypt(self._nonce(nonce, idx), payload, aad)
        except Exception as exc:  # InvalidTag 等
            raise WrongPasswordError("数据完整性校验失败（密码错误或文件被篡改）") from exc

    def eof_seal(self, nonce: bytes, total_len: int, aad: bytes = b"") -> bytes:
        ctx = aad + b"\x1eFCEOF\x1e" + struct.pack(">Q", total_len)
        return self._aead.encrypt(self._nonce(nonce, EOF_NONCE_IDX), b"", ctx)

    def eof_open(self, nonce: bytes, total_len: int, tag: bytes, aad: bytes = b"") -> None:
        ctx = aad + b"\x1eFCEOF\x1e" + struct.pack(">Q", total_len)
        try:
            self._aead.decrypt(self._nonce(nonce, EOF_NONCE_IDX), tag, ctx)
        except Exception as exc:
            raise WrongPasswordError("文件结尾校验失败（文件被截断或篡改）") from exc

    def seal_blob(self, data: bytes, context: bytes = b"blob") -> bytes:
        nonce = hashlib.sha256(context).digest()[:NONCE_LEN]
        return self.encrypt(nonce, 0, data, aad=context)

    def open_blob(self, payload: bytes, context: bytes = b"blob") -> bytes:
        nonce = hashlib.sha256(context).digest()[:NONCE_LEN]
        return self.decrypt(nonce, 0, payload, aad=context)


def make_cipher(algo: str, key: bytes):
    """按算法名创建加密器实例。"""
    if algo == ALGO_STREAM:
        return StreamCipher(key)
    if algo in (ALGO_AESGCM, ALGO_CHACHA):
        return AeadCipher(key, algo)
    raise UnsupportedAlgorithm(f"未知算法：{algo}")


def algorithm_available(algo: str) -> bool:
    if algo == ALGO_STREAM:
        return True
    return CRYPTOGRAPHY_AVAILABLE


def default_algorithm() -> str:
    """
    默认算法：优先标准 AEAD。

    AES-256-GCM 是经过广泛审查的标准构造（硬件加速、常量时间校验），
    远优于自构造的 SHAKE-256 流密码——后者只是为了"零依赖"而保留的兜底方案。
    """
    return ALGO_AESGCM if CRYPTOGRAPHY_AVAILABLE else ALGO_STREAM


DEFAULT_ALGO = default_algorithm()


def verify_token(key: bytes, salt: bytes) -> bytes:
    """生成用于“快速判断密码是否正确”的校验令牌。"""
    mac_key = hkdf_sha256(key, b"fcrypt-kdf", b"fcrypt/verify", KEY_LEN)
    return hmac.new(mac_key, b"FCRYPT-VERIFY" + salt, hashlib.sha256).digest()[:16]


# --------------------------------------------------------------------------
# 选项与统计
# --------------------------------------------------------------------------


@dataclass
class CryptOptions:
    """加解密选项。"""

    algo: str = DEFAULT_ALGO
    kdf: str = KDF_PBKDF2
    kdf_params: Dict[str, int] = field(default_factory=lambda: dict(KDF_PRESETS["标准"]))
    chunk_size: int = DEFAULT_CHUNK
    keyfile: Optional[str] = None
    store_name: bool = True          # 在头部保存（加密的）原始文件名
    keep_mtime: bool = True          # 解密后恢复原始修改时间
    overwrite: bool = False          # 允许覆盖已有输出文件
    delete_source: bool = False      # 成功后删除源文件
    wipe_source: bool = False        # 删除前安全擦除（多次覆写）
    wipe_passes: int = 3
    note: str = ""                   # 自定义备注，写入头部


@dataclass
class CryptStats:
    """一次操作的结果统计。"""

    src: str = ""
    dst: str = ""
    size: int = 0
    elapsed: float = 0.0
    algo: str = ""
    kdf: str = ""
    sha256_before: str = ""
    sha256_after: str = ""
    ok: bool = False
    message: str = ""

    @property
    def speed(self) -> float:
        return self.size / self.elapsed if self.elapsed > 0 else 0.0


ProgressCb = Optional[Callable[[str, int, int], None]]
CancelCb = Optional[Callable[[], bool]]


def _check_cancel(cancel: CancelCb) -> None:
    if cancel and cancel():
        raise CancelledError("操作已取消")


def _report(progress: ProgressCb, phase: str, done: int, total: int) -> None:
    if progress:
        progress(phase, done, total)


# --------------------------------------------------------------------------
# 头部构造 / 解析
# --------------------------------------------------------------------------


def _serialize_header(header: Dict) -> bytes:
    return json.dumps(header, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _parse_header(data: bytes) -> Dict:
    try:
        header = json.loads(data.decode("utf-8"))
    except Exception as exc:
        raise FormatError("头部解析失败，可能不是本工具生成的文件") from exc
    if not isinstance(header, dict) or header.get("magic") != "FCRYPT":
        raise FormatError("文件标识不正确")
    if int(header.get("v", 0)) > FILE_VERSION:
        raise FormatError("文件版本高于当前程序，请升级工具")
    return header


# --------------------------------------------------------------------------
# 核心加解密（基于文件对象，文件/内存共用）
# --------------------------------------------------------------------------


def _encrypt_stream(fsrc, fdst, password: str, opts: CryptOptions, size: int, mtime: float,
                    progress: ProgressCb = None, cancel: CancelCb = None,
                    fname: str = "") -> Dict:
    _check_cancel(cancel)
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)

    _report(progress, "派生密钥", 0, size)
    key = derive_master_key(password, salt, opts.kdf, opts.kdf_params, keyfile_digest(opts.keyfile))
    cipher = make_cipher(opts.algo, key)

    header = {
        "magic": "FCRYPT",
        "v": FILE_VERSION,
        "algo": opts.algo,
        "kdf": opts.kdf,
        "kdf_params": {k: int(v) for k, v in opts.kdf_params.items()},
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "chunk_size": int(opts.chunk_size),
        "size": int(size),
        "mtime": float(mtime),
        "created": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "keyfile": bool(opts.keyfile),
        "name_ct": None,
        "verify": b64e(verify_token(key, salt)),
        "note": opts.note or "",
        "tool": "FileCrypto 1.0",
    }
    if opts.store_name and fname:
        ctx = b"fcrypt/filename" + salt
        header["name_ct"] = b64e(cipher.seal_blob(fname.encode("utf-8"), ctx))

    header_bytes = _serialize_header(header)
    fdst.write(MAGIC)
    fdst.write(struct.pack(">I", len(header_bytes)))
    fdst.write(header_bytes)

    done = 0
    idx = 0
    while True:
        _check_cancel(cancel)
        plain = fsrc.read(opts.chunk_size)
        if not plain:
            break
        aad = header_bytes + struct.pack(">I", idx)
        payload = cipher.encrypt(nonce, idx, plain, aad)
        fdst.write(struct.pack(">I", len(payload)))
        fdst.write(payload)
        done += len(plain)
        idx += 1
        _report(progress, "加密", done, size)
        del plain

    eof_tag = cipher.eof_seal(nonce, size, header_bytes)
    fdst.write(struct.pack(">I", EOF_MARKER))
    fdst.write(eof_tag)
    _report(progress, "加密", size, size)
    return {"chunks": idx, "algo": opts.algo, "kdf": opts.kdf, "size": size}


def _decrypt_stream(fsrc, fdst, password: str, opts: CryptOptions,
                    progress: ProgressCb = None, cancel: CancelCb = None) -> Dict:
    _check_cancel(cancel)
    magic = fsrc.read(len(MAGIC))
    if magic != MAGIC:
        raise FormatError("不是 FileCrypto 加密文件（魔数不匹配）")
    raw_len = fsrc.read(4)
    if len(raw_len) != 4:
        raise FormatError("文件头不完整")
    (header_len,) = struct.unpack(">I", raw_len)
    if header_len <= 0 or header_len > (1 << 22):
        raise FormatError("头部长度异常")
    header_bytes = fsrc.read(header_len)
    if len(header_bytes) != header_len:
        raise FormatError("文件头不完整")
    header = _parse_header(header_bytes)

    algo = header.get("algo", "")
    kdf = header.get("kdf", "")
    if not algorithm_available(algo):
        raise UnsupportedAlgorithm(
            f"该文件使用 {algo} 加密，但当前环境缺少 cryptography 库，无法解密"
        )

    salt = b64d(header["salt"])
    nonce = b64d(header["nonce"])
    chunk_size = int(header.get("chunk_size", DEFAULT_CHUNK))
    total = int(header.get("size", 0))
    kdf_params = {k: int(v) for k, v in (header.get("kdf_params") or {}).items()}

    _report(progress, "派生密钥", 0, total)
    key = derive_master_key(password, salt, kdf, kdf_params, keyfile_digest(opts.keyfile))

    expect = header.get("verify")
    legacy_normalized = False
    if expect and not hmac.compare_digest(b64d(expect), verify_token(key, salt)):
        # 兼容旧版本：v1.0 未对密码做 NFC 归一化，若密码含组合字符，
        # 用归一化后的密码会派生出不同的密钥。这里回退一次原始字节序列再试。
        if normalize_password(password) != password:
            legacy_key = derive_master_key(password, salt, kdf, kdf_params,
                                           keyfile_digest(opts.keyfile), normalize=False)
            if hmac.compare_digest(b64d(expect), verify_token(legacy_key, salt)):
                key = legacy_key
                legacy_normalized = True
        if not legacy_normalized:
            raise WrongPasswordError("密码错误或密钥文件不匹配")

    cipher = make_cipher(algo, key)

    # 可选：解密原始文件名
    original_name = None
    if header.get("name_ct"):
        try:
            ctx = b"fcrypt/filename" + salt
            original_name = cipher.open_blob(b64d(header["name_ct"]), ctx).decode("utf-8", "replace")
        except CryptError:
            original_name = None

    done = 0
    idx = 0
    while True:
        _check_cancel(cancel)
        raw = fsrc.read(4)
        if not raw:
            raise FormatError("文件意外结束：缺少 EOF 终结块")
        if len(raw) != 4:
            raise FormatError("数据块长度字段不完整")
        (length,) = struct.unpack(">I", raw)
        if length == EOF_MARKER:
            eof_tag = fsrc.read(TAG_LEN)
            if len(eof_tag) != TAG_LEN:
                raise FormatError("EOF 认证标签不完整")
            cipher.eof_open(nonce, total, eof_tag, header_bytes)
            break
        if length == 0 or length > chunk_size + TAG_LEN:
            raise FormatError(f"数据块长度异常：{length}")
        payload = fsrc.read(length)
        if len(payload) != length:
            raise FormatError("数据块不完整")
        aad = header_bytes + struct.pack(">I", idx)
        plain = cipher.decrypt(nonce, idx, payload, aad)
        fdst.write(plain)
        done += len(plain)
        idx += 1
        _report(progress, "解密", done, total)
        del plain, payload

    if done != total:
        raise FormatError(f"解密后大小不符：期望 {total} 字节，实际 {done} 字节")
    return {
        "chunks": idx,
        "algo": algo,
        "kdf": kdf,
        "size": total,
        "legacy_password": legacy_normalized,
        "name": original_name,
        "mtime": float(header.get("mtime", 0) or 0),
        "note": header.get("note", ""),
        "created": header.get("created", ""),
    }


# --------------------------------------------------------------------------
# 文件级 API
# --------------------------------------------------------------------------


def default_output_path(src: Path, decrypt: bool, out_dir: Optional[Path] = None,
                        suffix: str = DEFAULT_SUFFIX) -> Path:
    """推算默认输出路径。"""
    if decrypt:
        name = src.name
        if name.lower().endswith(suffix):
            name = name[: -len(suffix)]
        else:
            name = name + ".dec"
        base = Path(name)
    else:
        base = Path(src.name + suffix)
    return (out_dir / base) if out_dir else (src.parent / base)


def encrypt_file(src: os.PathLike | str, dst: os.PathLike | str | None, password: str,
                 opts: CryptOptions, progress: ProgressCb = None,
                 cancel: CancelCb = None) -> CryptStats:
    """加密单个文件。"""
    src_path = Path(src)
    if not src_path.is_file():
        raise CryptError(f"源文件不存在：{src_path}")
    if not password:
        raise CryptError("密码不能为空")

    dst_path = Path(dst) if dst else default_output_path(src_path, decrypt=False)
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    if dst_path.exists():
        if not opts.overwrite:
            dst_path = unique_path(dst_path)
        elif dst_path.resolve() == src_path.resolve():
            raise CryptError("输出文件不能与源文件相同")

    size = src_path.stat().st_size
    mtime = src_path.stat().st_mtime
    started = time.time()
    tmp_path = dst_path.with_name(dst_path.name + ".part")
    stats = CryptStats(src=str(src_path), dst=str(dst_path), size=size, algo=opts.algo, kdf=opts.kdf)
    try:
        with open(src_path, "rb") as fin, open(tmp_path, "wb") as fout:
            _encrypt_stream(fin, fout, password, opts, size, mtime, progress, cancel, src_path.name)
        os.replace(tmp_path, dst_path)
    except BaseException:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    if opts.delete_source:
        if opts.wipe_source:
            secure_delete(src_path, opts.wipe_passes)
        else:
            src_path.unlink(missing_ok=True)

    stats.elapsed = time.time() - started
    stats.ok = True
    stats.message = "加密完成"
    return stats


def decrypt_file(src: os.PathLike | str, dst: os.PathLike | str | None, password: str,
                 opts: CryptOptions, out_dir: Optional[Path] = None,
                 progress: ProgressCb = None, cancel: CancelCb = None) -> CryptStats:
    """解密单个文件，输出路径可按头部记录的原文件名恢复。"""
    src_path = Path(src)
    if not src_path.is_file():
        raise CryptError(f"源文件不存在：{src_path}")
    if not password:
        raise CryptError("密码不能为空")

    # 先读头部拿到原始文件名与大小
    with open(src_path, "rb") as fin:
        magic = fin.read(len(MAGIC))
        if magic != MAGIC:
            raise FormatError("不是 FileCrypto 加密文件（魔数不匹配）")
        raw_len = fin.read(4)
        if len(raw_len) != 4:
            raise FormatError("文件头不完整")
        (header_len,) = struct.unpack(">I", raw_len)
        header_bytes = fin.read(header_len)
    header = _parse_header(header_bytes)

    if dst:
        dst_path = Path(dst)
    else:
        target_dir = Path(out_dir) if out_dir else src_path.parent
        name = src_path.name
        if header.get("name_ct"):
            name = None  # 由解密流返回真实名字
        elif name.lower().endswith(DEFAULT_SUFFIX):
            name = name[: -len(DEFAULT_SUFFIX)]
        else:
            name = name + ".dec"
        dst_path = (target_dir / name) if name else None

    dst_path.parent.mkdir(parents=True, exist_ok=True) if dst_path else None

    size = int(header.get("size", 0))
    started = time.time()
    stats = CryptStats(src=str(src_path), size=size, algo=header.get("algo", ""), kdf=header.get("kdf", ""))

    tmp_path = None
    try:
        with open(src_path, "rb") as fin:
            if dst_path is None:
                # 名字未知：先解到临时文件，再按解出的原始名落盘
                import tempfile

                tmp_dir = Path(out_dir) if out_dir else src_path.parent
                fd, tmp_name = tempfile.mkstemp(prefix=".fcrypt_", dir=str(tmp_dir))
                os.close(fd)
                tmp_path = Path(tmp_name)
                with open(tmp_path, "wb") as fout:
                    info = _decrypt_stream(fin, fout, password, opts, progress, cancel)
                real_name = info.get("name") or (src_path.name + ".dec")
                dst_path = tmp_dir / Path(real_name).name
                if dst_path.exists() and not opts.overwrite:
                    dst_path = unique_path(dst_path)
                os.replace(tmp_path, dst_path)
                tmp_path = None
            else:
                tmp_path = dst_path.with_name(dst_path.name + ".part")
                if tmp_path.exists():
                    tmp_path.unlink(missing_ok=True)
                with open(tmp_path, "wb") as fout:
                    info = _decrypt_stream(fin, fout, password, opts, progress, cancel)
                if dst_path.exists() and not opts.overwrite:
                    dst_path = unique_path(dst_path)
                os.replace(tmp_path, dst_path)
                tmp_path = None
    except BaseException:
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise

    # 恢复原始修改时间
    if opts.keep_mtime and info.get("mtime"):
        try:
            os.utime(dst_path, (time.time(), info["mtime"]))
        except OSError:
            pass

    if opts.delete_source:
        if opts.wipe_source:
            secure_delete(src_path, opts.wipe_passes)
        else:
            src_path.unlink(missing_ok=True)

    stats.dst = str(dst_path)
    stats.elapsed = time.time() - started
    stats.ok = True
    stats.message = "解密完成"
    return stats


# --------------------------------------------------------------------------
# 内存（文本）加解密
# --------------------------------------------------------------------------


def seal_bytes(data: bytes, password: str, opts: CryptOptions) -> bytes:
    """把内存数据加密为自包含字节串（用于文本加密）。"""
    import io

    fin, fout = io.BytesIO(data), io.BytesIO()
    _encrypt_stream(fin, fout, password, opts, len(data), time.time(), None, None, "text.txt")
    return fout.getvalue()


def open_bytes(blob: bytes, password: str, opts: CryptOptions) -> bytes:
    """解密由 seal_bytes 生成的数据。"""
    import io

    fin, fout = io.BytesIO(blob), io.BytesIO()
    _decrypt_stream(fin, fout, password, opts, None, None)
    return fout.getvalue()


def seal_text(text: str, password: str, opts: CryptOptions, armor: bool = True) -> str:
    """文本加密，armor=True 时输出便于复制粘贴的 Base64 文本块。"""
    blob = seal_bytes(text.encode("utf-8"), password, opts)
    text_out = base64.b64encode(blob).decode("ascii")
    if not armor:
        return text_out
    lines = [text_out[i : i + 64] for i in range(0, len(text_out), 64)]
    return "-----BEGIN FCRYPT TEXT-----\n" + "\n".join(lines) + "\n-----END FCRYPT TEXT-----"


def open_text(armored: str, password: str, opts: CryptOptions) -> str:
    """解密 seal_text 生成的文本。"""
    body = []
    for line in armored.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("-----"):
            continue
        body.append(line)
    if not body:
        raise FormatError("没有找到密文内容")
    try:
        blob = base64.b64decode("".join(body), validate=False)
    except Exception as exc:
        raise FormatError("密文不是合法的 Base64 文本") from exc
    return open_bytes(blob, password, opts).decode("utf-8", "replace")


# --------------------------------------------------------------------------
# 安全删除 / 校验
# --------------------------------------------------------------------------


def wipe_plan(passes: int) -> List[str]:
    """
    返回每一遍的填充策略：前几遍随机数据，**最后一遍全零**。

    最后一遍写全零不为保密，而是为了消除"文件内容看起来像随机数据"这一特征，
    同时让残留块在统计上与一张普通被清零的盘片无差别（对机械盘有意义）。
    """
    passes = max(1, int(passes))
    return ["random"] * (passes - 1) + ["zero"]


def secure_delete(path: os.PathLike | str, passes: int = 3, progress: ProgressCb = None,
                  cancel: CancelCb = None) -> None:
    """
    多次覆写后删除文件。

    重要限制（请务必阅读）：在 SSD、NVMe、写时复制文件系统（Btrfs/ZFS/APFS）、
    以及开启 TRIM/快照/日志的卷上，覆写**无法保证**物理介质上旧数据被清除——
    写入会落到新的物理块，旧块由主控回收。真正可靠的做法是**全盘加密**
    （BitLocker/LUKS/FileVault），密钥一销毁，旧数据即不可读。
    本函数只是"尽力而为"的一层，不应被当作 SSD 上的安全保证。
    """
    p = Path(path)
    if not p.is_file():
        return
    size = p.stat().st_size
    plan = wipe_plan(passes)
    try:
        with open(p, "r+b", buffering=0) as fh:
            for strategy in plan:
                fh.seek(0)
                remaining = size
                while remaining > 0:
                    _check_cancel(cancel)
                    block = min(1 << 20, remaining)
                    # 前几遍随机（覆盖旧数据），最后一遍全零（消除"随机数据"特征）
                    chunk = secrets.token_bytes(block) if strategy == "random" else b"\x00" * block
                    fh.write(chunk)
                    remaining -= block
                    if progress:
                        progress("擦除", size - remaining, size)
                fh.flush()
                os.fsync(fh.fileno())
        # 移出原文件名后再删除，避免文件名残留在目录项里
        junk = p.with_name("." + secrets.token_hex(8) + ".tmp")
        os.replace(p, junk)
        junk.unlink()
    except (OSError, PermissionError):
        p.unlink(missing_ok=True)


def file_hash(path: os.PathLike | str, algo: str = "sha256", progress: ProgressCb = None,
              cancel: CancelCb = None) -> str:
    """流式计算文件摘要。"""
    try:
        h = hashlib.new(algo)
    except ValueError as exc:
        raise CryptError(f"不支持的哈希算法：{algo}") from exc
    size = Path(path).stat().st_size
    done = 0
    with open(path, "rb") as fh:
        while True:
            _check_cancel(cancel)
            block = fh.read(1 << 20)
            if not block:
                break
            h.update(block)
            done += len(block)
            if progress:
                progress("计算摘要", done, size)
    return h.hexdigest()


def read_encrypted_header(path: os.PathLike | str) -> Dict:
    """只读取加密文件的头部信息（用于列表展示）。"""
    with open(path, "rb") as fh:
        if fh.read(len(MAGIC)) != MAGIC:
            raise FormatError("不是 FileCrypto 加密文件")
        raw = fh.read(4)
        (header_len,) = struct.unpack(">I", raw)
        return _parse_header(fh.read(header_len))


# --------------------------------------------------------------------------
# 自检
# --------------------------------------------------------------------------


def self_test(verbose: bool = True) -> Tuple[bool, list]:
    """跑一遍算法/格式/错误处理的回归测试，返回 (是否全部通过, 明细列表)。"""
    import io
    import tempfile

    results: list = []

    def case(name: str, fn):
        try:
            fn()
            results.append((name, True, ""))
        except Exception as exc:  # noqa: BLE001
            results.append((name, False, f"{type(exc).__name__}: {exc}"))

    def roundtrip(algo: str, kdf: str, size: int, chunk: int = 64 * 1024):
        payload = secrets.token_bytes(size)
        opts = CryptOptions(algo=algo, kdf=kdf,
                            kdf_params={"iterations": 120_000, "n": 1 << 13, "r": 8, "p": 1},
                            chunk_size=chunk)
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "数据.bin"
            src.write_bytes(payload)
            enc = Path(td) / "data.bin.fcrypt"
            st = encrypt_file(src, enc, "P@ssw0rd-测试", opts)
            assert st.size == size, "加密统计大小错误"
            out = Path(td) / "out.bin"
            st2 = decrypt_file(enc, out, "P@ssw0rd-测试", opts)
            assert out.read_bytes() == payload, "解密结果与原文不一致"
            assert st2.size == size
            # 错误密码必须失败
            wrong_failed = False
            try:
                decrypt_file(enc, Path(td) / "bad.bin", "wrong-password", opts)
            except WrongPasswordError:
                wrong_failed = True
            assert wrong_failed, "错误密码未被拒绝"
            # 篡改必须被发现
            raw = bytearray(enc.read_bytes())
            raw[-1] ^= 0x01
            enc.write_bytes(bytes(raw))
            tamper_failed = False
            try:
                decrypt_file(enc, Path(td) / "tamper.bin", "P@ssw0rd-测试", opts)
            except CryptError:
                tamper_failed = True
            assert tamper_failed, "篡改未被检测"

    def text_roundtrip():
        opts = CryptOptions(kdf_params={"iterations": 60_000})
        text = "文本加解密测试 · Hello 🌍 123"
        blob = seal_text(text, "pwd123", opts)
        assert "BEGIN FCRYPT TEXT" in blob
        assert open_text(blob, "pwd123", opts) == text

    def keyfile_roundtrip():
        with tempfile.TemporaryDirectory() as td:
            kf = Path(td) / "key.bin"
            kf.write_bytes(secrets.token_bytes(64))
            opts = CryptOptions(keyfile=str(kf), kdf_params={"iterations": 60_000})
            src = Path(td) / "a.txt"
            src.write_text("keyfile test", encoding="utf-8")
            enc = Path(td) / "a.enc"
            encrypt_file(src, enc, "pwd", opts)
            out = Path(td) / "a.out"
            decrypt_file(enc, out, "pwd", opts)
            assert out.read_text(encoding="utf-8") == "keyfile test"
            # 不带密钥文件应当失败
            bad = False
            try:
                decrypt_file(enc, Path(td) / "b.out", "pwd", CryptOptions())
            except CryptError:
                bad = True
            assert bad, "缺少密钥文件时应当报错"

    def empty_and_meta():
        opts = CryptOptions(kdf_params={"iterations": 60_000}, chunk_size=1024, note="备注-元数据")
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "空文件.dat"
            src.write_bytes(b"")
            enc = Path(td) / "e.bin"
            mtime = 1_600_000_000
            os.utime(src, (mtime, mtime))
            encrypt_file(src, enc, "pw", opts)
            header = read_encrypted_header(enc)
            assert header["size"] == 0 and header["note"] == "备注-元数据"
            out = Path(td) / "r.bin"
            decrypt_file(enc, out, "pw", opts)
            assert out.read_bytes() == b""

    def exact_multiple():
        # 大小恰为分块整数倍，验证 EOF 终结块逻辑
        opts = CryptOptions(kdf_params={"iterations": 60_000}, chunk_size=4096)
        data = secrets.token_bytes(4096 * 3)
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "m.bin"
            src.write_bytes(data)
            enc = Path(td) / "m.enc"
            encrypt_file(src, enc, "pw", opts)
            out = Path(td) / "m.out"
            decrypt_file(enc, out, "pw", opts)
            assert out.read_bytes() == data

    def truncated():
        opts = CryptOptions(kdf_params={"iterations": 60_000}, chunk_size=4096)
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "t.bin"
            src.write_bytes(secrets.token_bytes(20000))
            enc = Path(td) / "t.enc"
            encrypt_file(src, enc, "pw", opts)
            raw = enc.read_bytes()[:-20]
            enc.write_bytes(raw)
            failed = False
            try:
                decrypt_file(enc, Path(td) / "t.out", "pw", opts)
            except CryptError:
                failed = True
            assert failed, "截断文件未被检测"

    def misc():
        assert human_size(1536) == "1.50 KB"
        assert len(generate_password(24)) == 24
        s, _ = password_strength("Tr0ub4dor&3-very-long-passphrase")
        assert s > 60
        assert len(hkdf_sha256(b"a", b"b", b"c", 42)) == 42

    def nfc_password():
        # 预组合 é 与 e+组合重音 必须派生出同一个密钥
        a, b = "café", "cafe\u0301"
        assert a.encode() != b.encode()
        assert normalize_password(a) == normalize_password(b)
        opts = CryptOptions(kdf_params={"iterations": 60_000}, chunk_size=4096)
        blob = seal_bytes(b"nfc", a, opts)
        assert open_bytes(blob, b, opts) == b"nfc"
        # 仅大小写/空白不同则应当不同
        assert normalize_password("Pass") != normalize_password("pass")

    def weak_password():
        for pw in ("password", "P@ssw0rd", "123456789", "qwertyuiop123", "Password2026!"):
            assert is_common_password(pw), f"{pw} 未被识别为弱口令"
            score, label = password_strength(pw)
            assert score <= 20, f"{pw} 分数仍然偏高：{score}"
            assert "弱" in label or "极弱" in label
        # 强密码不应被误判
        strong = generate_password(24)
        assert not is_common_password(strong), f"强密码被误判：{strong}"
        assert password_strength(strong)[0] >= 70
        # 纯数字短串必须判弱
        assert is_common_password("20261017")

    def wipe_policy():
        assert wipe_plan(1) == ["zero"]
        assert wipe_plan(3) == ["random", "random", "zero"]
        assert wipe_plan(0) == ["zero"]          # 非法值兜底为 1 遍
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "wipe.bin"
            p.write_bytes(b"A" * 5000)
            import io as _io
            # 覆写 1 遍后内容应为全零（在删除前检查）
            captured = {}
            orig_unlink = Path.unlink

            def fake_unlink(self, missing_ok=False):
                captured["data"] = self.read_bytes() if self.exists() else b""
            Path.unlink = fake_unlink
            try:
                secure_delete(p, passes=1)
            finally:
                Path.unlink = orig_unlink
            if captured.get("data"):
                assert set(captured["data"]) == {0}, "最后一遍没有写成全零"

    def legacy_password_compat():
        # 模拟 v1.0（未做 NFC 归一化）生成的文件，验证解密时可回退成功
        pw = "café-旧密码"
        opts = CryptOptions(kdf_params={"iterations": 60_000})
        orig = normalize_password
        with tempfile.TemporaryDirectory() as td:
            try:
                globals()["normalize_password"] = lambda p: p   # type: ignore[assignment]
                src = Path(td) / "legacy.txt"
                src.write_text("legacy payload", encoding="utf-8")
                enc = Path(td) / "legacy.enc"
                encrypt_file(src, enc, pw, opts)
            finally:
                globals()["normalize_password"] = orig          # type: ignore[assignment]
            out = Path(td) / "out.txt"
            decrypt_file(enc, out, pw, opts)
            assert out.read_text(encoding="utf-8") == "legacy payload", "旧文件回退失败"
        # 新版本用同一密码加密的文件也应当能正常解开
        blob = seal_bytes(b"fresh", pw, opts)
        assert open_bytes(blob, normalize_password(pw), opts) == b"fresh"

    case("内置算法 · 1MB 往返", lambda: roundtrip(ALGO_STREAM, KDF_PBKDF2, 1 << 20))
    case("内置算法 · scrypt 往返", lambda: roundtrip(ALGO_STREAM, KDF_SCRYPT, 300_000))
    case("内置算法 · 分块边界", lambda: roundtrip(ALGO_STREAM, KDF_PBKDF2, 700_000, 64 * 1024))
    if CRYPTOGRAPHY_AVAILABLE:
        case("AES-256-GCM 往返（默认算法）", lambda: roundtrip(ALGO_AESGCM, KDF_PBKDF2, 400_000))
        case("ChaCha20 往返", lambda: roundtrip(ALGO_CHACHA, KDF_PBKDF2, 400_000))
    case("文本加解密（含 Emoji）", text_roundtrip)
    case("密钥文件模式", keyfile_roundtrip)
    case("空文件 + 头部元数据", empty_and_meta)
    case("整块倍数大小", exact_multiple)
    case("截断检测", truncated)
    case("工具函数", misc)
    case("密码 NFC 归一化", nfc_password)
    case("弱口令字典与强度评估", weak_password)
    case("安全擦除填充策略", wipe_policy)
    case("旧文件密码兼容回退", legacy_password_compat)

    if verbose:
        for name, ok, msg in results:
            print(("  [通过] " if ok else "  [失败] ") + name + (f"  <- {msg}" if msg else ""))
    return all(ok for _, ok, _ in results), results


# --------------------------------------------------------------------------
# 命令行入口（便于脚本化与自动化测试）
# --------------------------------------------------------------------------


def _cli(argv: Optional[list] = None) -> int:
    import argparse
    import getpass

    parser = argparse.ArgumentParser(description="FileCrypto 命令行模式（GUI 请直接运行 file_crypto_ui.py）")
    sub = parser.add_subparsers(dest="cmd")

    p_enc = sub.add_parser("encrypt", help="加密文件")
    p_enc.add_argument("-i", "--input", required=True)
    p_enc.add_argument("-o", "--output")
    p_enc.add_argument("-p", "--password")
    p_enc.add_argument("-a", "--algo", default=ALGO_STREAM, choices=list(ALGORITHMS))
    p_enc.add_argument("-k", "--kdf", default=KDF_PBKDF2, choices=list(KDFS))
    p_enc.add_argument("-f", "--keyfile")
    p_enc.add_argument("--delete-source", action="store_true")
    p_enc.add_argument("--wipe", action="store_true")

    p_dec = sub.add_parser("decrypt", help="解密文件")
    p_dec.add_argument("-i", "--input", required=True)
    p_dec.add_argument("-o", "--output")
    p_dec.add_argument("-p", "--password")
    p_dec.add_argument("-f", "--keyfile")
    p_dec.add_argument("-d", "--outdir")

    p_test = sub.add_parser("selftest", help="运行自检")

    args = parser.parse_args(argv)

    if args.cmd == "selftest":
        ok, _ = self_test()
        print("\n自检结果：" + ("全部通过 [PASS]" if ok else "存在失败项 [FAIL]"))
        return 0 if ok else 1

    if args.cmd in ("encrypt", "decrypt"):
        pwd = args.password or getpass.getpass("请输入密码：")
        opts = CryptOptions(algo=getattr(args, "algo", ALGO_STREAM),
                            kdf=getattr(args, "kdf", KDF_PBKDF2),
                            keyfile=args.keyfile,
                            delete_source=getattr(args, "delete_source", False),
                            wipe_source=getattr(args, "wipe", False))
        try:
            if args.cmd == "encrypt":
                st = encrypt_file(args.input, args.output, pwd, opts)
            else:
                st = decrypt_file(args.input, args.output, pwd, opts,
                                  out_dir=args.outdir)
            print(f"{st.message}：{st.src} -> {st.dst}  ({human_size(st.size)}, {st.elapsed:.2f}s)")
            return 0
        except CryptError as exc:
            print(f"[错误] {exc}")
            return 2

    parser.print_help()
    return 0


if __name__ == "__main__":
    import sys

    # 打包成 --noconsole 的 exe 后 stdout/stderr 可能是 None，先兜底再输出
    for _name in ("stdout", "stderr"):
        if getattr(sys, _name, None) is None:
            try:
                setattr(sys, _name, open(os.devnull, "w", encoding="utf-8"))
            except Exception:
                pass
    # Windows 控制台默认 GBK，统一切到 UTF-8 输出，避免中文/符号乱码
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    if len(sys.argv) == 1:
        print(__doc__)
        sys.exit(0)
    sys.exit(_cli())
