"""Pure-Python Ed25519 signatures (RFC 8032), stdlib only.

Written from the RFC 8032 specification for bridge-guard, which is
stdlib-only by design and cannot take a crypto dependency. Group
operations use extended twisted-Edwards coordinates (no field
inversion inside scalar multiplication), and scalar multiplication
runs over lazily built 4-bit window tables, cached per point, so
repeated derivations and verifications against the same keys stay
fast enough for a test suite.

Only three operations are exposed: derive a public key from a
32-byte seed, sign with a seed, and verify with a public key. A
public key here is mathematically unable to produce a signature:
signing and verification share no secret material.
"""
import hashlib

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _recover_x(y, sign):
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * _I % _P
    if (x * x - xx) % _P != 0:
        return None
    if x % 2 != sign:
        x = _P - x
    return x


_BY = 4 * pow(5, _P - 2, _P) % _P
_BX = _recover_x(_BY, 0)
# Extended coordinates: (X, Y, Z, T) with x = X/Z, y = Y/Z, T = XY/Z.
_B = (_BX, _BY, 1, _BX * _BY % _P)
_IDENTITY = (0, 1, 1, 0)


def _add(p, q):
    px, py, pz, pt = p
    qx, qy, qz, qt = q
    a = (py - px) * (qy - qx) % _P
    b = (py + px) * (qy + qx) % _P
    c = 2 * _D * pt * qt % _P
    d = 2 * pz * qz % _P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _double(p):
    px, py, pz, _pt = p
    a = px * px % _P
    b = py * py % _P
    c = 2 * pz * pz % _P
    d = -a % _P
    e = ((px + py) * (px + py) - a - b) % _P
    g = d + b
    f = g - c
    h = d - b
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


class _WindowTable:
    """Multiples of one point, 16 per 4-bit window, built lazily:
    row w holds d * 16**w * point for d in 0..15."""

    def __init__(self, point):
        self._rows = []
        self._next = point

    def _grow(self):
        row = [_IDENTITY]
        for _ in range(15):
            row.append(_add(row[-1], self._next))
        self._rows.append(row)
        nxt = self._next
        for _ in range(4):
            nxt = _double(nxt)
        self._next = nxt

    def mul(self, scalar):
        result = _IDENTITY
        window = 0
        while scalar:
            digit = scalar & 15
            if digit:
                while len(self._rows) <= window:
                    self._grow()
                result = _add(result, self._rows[window][digit])
            scalar >>= 4
            window += 1
        return result


_BASE_TABLE = _WindowTable(_B)
_POINT_TABLES = {}
_POINT_TABLE_LIMIT = 256


def _table_for(point, cache_key):
    table = _POINT_TABLES.get(cache_key)
    if table is None:
        table = _WindowTable(point)
        if len(_POINT_TABLES) < _POINT_TABLE_LIMIT:
            _POINT_TABLES[cache_key] = table
    return table


def _encode_point(point):
    x = point[0] * pow(point[2], _P - 2, _P) % _P
    y = point[1] * pow(point[2], _P - 2, _P) % _P
    bits = y | ((x & 1) << 255)
    return bits.to_bytes(32, "little")


def _decode_point(data):
    if len(data) != 32:
        return None
    bits = int.from_bytes(data, "little")
    sign = bits >> 255
    y = bits & ((1 << 255) - 1)
    if y >= _P:
        return None
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _clamp(h):
    a = int.from_bytes(h, "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a


_PUBLIC_CACHE = {}
_DECODE_CACHE = {}


def _points_equal(p, q):
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 \
        and (p[1] * q[2] - q[1] * p[2]) % _P == 0


def publickey(seed):
    """The 32-byte public key for a 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("an Ed25519 seed is 32 bytes")
    cached = _PUBLIC_CACHE.get(seed)
    if cached is not None:
        return cached
    digest = hashlib.sha512(seed).digest()
    public = _encode_point(_BASE_TABLE.mul(_clamp(digest[:32])))
    if len(_PUBLIC_CACHE) < 1024:
        _PUBLIC_CACHE[seed] = public
    return public


def sign(seed, message):
    """The 64-byte Ed25519 signature of message under seed."""
    if len(seed) != 32:
        raise ValueError("an Ed25519 seed is 32 bytes")
    digest = hashlib.sha512(seed).digest()
    a = _clamp(digest[:32])
    public = publickey(seed)
    r = int.from_bytes(
        hashlib.sha512(digest[32:] + message).digest(), "little") % _L
    r_bytes = _encode_point(_BASE_TABLE.mul(r))
    k = int.from_bytes(
        hashlib.sha512(r_bytes + public + message).digest(),
        "little") % _L
    s = (r + k * a) % _L
    return r_bytes + s.to_bytes(32, "little")


def verify(public, message, signature):
    """True iff signature is a valid Ed25519 signature of message
    under public. Never raises on malformed input."""
    if len(public) != 32 or len(signature) != 64:
        return False
    a_point = _DECODE_CACHE.get(public)
    if a_point is None:
        a_point = _decode_point(public)
        if a_point is None:
            return False
        if len(_DECODE_CACHE) < 256:
            _DECODE_CACHE[public] = a_point
    r_bytes = signature[:32]
    r_point = _decode_point(r_bytes)
    if r_point is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(
        hashlib.sha512(r_bytes + public + message).digest(), "little")
    left = _BASE_TABLE.mul(s)
    right = _add(r_point, _table_for(a_point, public).mul(k))
    return _points_equal(left, right)
