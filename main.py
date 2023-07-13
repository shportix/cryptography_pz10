import hashlib
import gmpy2

from ecdsa import curves, ellipticcurve
import secrets


class ECPoint:
    def __init__(self, x, y):
        self.x = x
        self.y = y

def ec_point_gen(x, y):
    point = ECPoint(x, y)
    if is_on_curve_check(point):
        return point
    return False


def base_point_g_get():
    _curve = curves.NIST256p
    _base_point = _curve.generator
    _base_point = ECPoint(_base_point.x(), _base_point.y())
    return _base_point

def get_base_curve():
    _curve = curves.NIST256p.curve
    return _curve

def is_on_curve_check( _point: ECPoint):
    try:
        _curve  = get_base_curve()
        _f = ellipticcurve.Point(_curve, _point.x, _point.y)
    except AssertionError:
        return False
    return True

def add_ec_points(_a: ECPoint, _b: ECPoint):
    _curve = get_base_curve()
    _a = ellipticcurve.Point(_curve, _a.x, _a.y)
    _b = ellipticcurve.Point(_curve, _b.x, _b.y)
    _c = _a + _b
    _c = ECPoint(_c.x(), _c.y())
    return _c

def double_ec_points(point: ECPoint):
    _curve = get_base_curve()
    point = ellipticcurve.Point(_curve, point.x, point.y)
    point.double()
    point = ECPoint(point.x(), point.y())
    return point

def scalar_multiple(k, point: ECPoint):
    _curve = get_base_curve()
    point = ellipticcurve.Point(_curve, point.x, point.y)
    point_2 = k * point
    point_2 = ECPoint(point_2.x(),point_2.y())
    return point_2

def is_equal_points(point_1: ECPoint, point_2: ECPoint):
    return (point_1.x == point_2.x) and (point_1.y == point_2.y)

def ec_point_to_string(point: ECPoint):
    string = str(point.x) + " " + str(point.y)
    return string

def string_to_ec_point(string:str):
    res = string.split()
    point = ECPoint(int(res[0]), int(res[1]))
    return point

def print_ec_point(point: ECPoint):
    print(f"x: {point.x}, y: {point.y}")

def private_key_gen():
    curve = curves.NIST256p
    key = secrets.randbelow(curve.order)
    return key

def public_key_gen(private_key):
    g = base_point_g_get()
    key = scalar_multiple(private_key, g)
    return key


def sign_message(private_key, message: bytes):
    r = private_key_gen()
    R = public_key_gen(r)
    m = hashlib.sha256(message).digest()
    e = int.from_bytes(m, 'big') ^ R.x
    s = (r - private_key * e) % curves.NIST256p.order
    return serialize_signature(s, e)


def verify(public_key, signature, message: bytes):
    s, e = deserialize_signature(signature)
    m = hashlib.sha256(message).digest()
    g = base_point_g_get()
    g = scalar_multiple(s, g)
    public_key = scalar_multiple(e, public_key)
    R = add_ec_points(g, public_key)
    e1 = int.from_bytes(m, 'big') ^ R.x
    if e1 != e:
        return False
    return True

def serialize_private_key(private_key):
    return hex(private_key)[2:]

def deserialize_private_key(ser_private_key):
    return int(ser_private_key, 16)

def serialize_public_key(public_key: ECPoint):
    return f'x:{public_key.x} y:{public_key.y}'

def deserialize_public_key(ser_public_key):
    p = ser_public_key.split(" ")
    x = int(p[0][2:])
    y = int(p[1][2:])
    return ECPoint(x, y)

def serialize_signature(s, e):
    return f"s:{s} e:{e}"

def deserialize_signature(ser_signature: str):
    result = ser_signature.split(" ")
    return int(result[0][2:]), int(result[1][2:])


if __name__ == '__main__':
    private_key = serialize_private_key(private_key_gen())
    print(f"private key: {private_key}")
    private_key = deserialize_private_key(private_key)
    public_key = public_key_gen(private_key)
    public_key = serialize_public_key(public_key)
    print(f"public key: {public_key}")
    public_key = deserialize_public_key(public_key)
    string = b"hello world"
    signature = sign_message(private_key, string)
    print(f"signature: {signature}")
    res = verify(public_key, signature, string)
    print(f"is valid: {res}")
    print()

