from dataclasses import dataclass
from base64 import b64decode
from hashlib import sha256
from json import load
from sys import argv

from arc4 import ARC4

@dataclass
class Request:
    """
    Specifies the request 
    """
    data: str
    nonce: str
    rc4_hash: str
    signature: str


def decrypt_response(body: str, ssecurity: str, nonce: str) -> bytes:
    body_bytes = b64decode(body)
    ssecurity_bytes = b64decode(ssecurity)
    nonce_bytes = b64decode(nonce)

    key = sha256(ssecurity_bytes + nonce_bytes).digest()
    return ARC4(key).decrypt(body_bytes)

def main(in_filename: str):
    with open(in_filename, 'rt') as json_file:
        json_data = load(json_file)

        ssecurity = json_data['ssecurity']
        nonce = json_data['nonce']

        req_body = json_data['req_data']
        output = decrypt_response(req_body, ssecurity, nonce)
        print(f'req body: {output}')

        res_data = json_data['res_data']
        output = decrypt_response(res_data, ssecurity, nonce)
        print(f'res data: {output}')

if __name__ == '__main__':
    in_filename = argv[1]
    main(in_filename)
