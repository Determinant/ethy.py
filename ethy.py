#! /bin/env python3
# MIT License
#
# Copyright (c) 2018 Ted Yin <tederminant@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
#
# This little script offers decryption and verification of the existing
# Ethereum wallets, as well as generation of a new wallet. You can use any
# utf-8 string as the password, which could provide with better security
# against the brute-force attack.

# Use at your own risk.
#
# Example:
# python ./ethy.py --verify-key # unlock the wallet and verify whether the
#                               # encrypted private key matches the address
# python ./ethy.py --show-key # reveal the private key (secp256k1)
#
# python ./ethy.py --gen > mywallet.json         # generate a regular wallet (1s)
# python ./ethy.py --gen --light > mywallet.json # generate a wallet (fast)

import os, sys, json, argparse
from hashlib import scrypt
from uuid import uuid4
from getpass import getpass as _getpass
from collections import Counter as Histogram
from math import log
from Crypto.Cipher import AES
from Crypto.Util import Counter
from sha3 import keccak_256
from ecdsa import SigningKey, SECP256k1

err = sys.stderr

import collections

def entropy(data):
    n = len(data)
    return sum([-p * log(p, 2) for p in
                [c / n for _,c in Histogram(data).items()]])

def getpass():
    return _getpass().encode('utf-8')

def getpass2():
    passwd = _getpass('Enter your wallet password (utf-8): ')
    rpasswd = _getpass('Repeat the password: ')
    if passwd != rpasswd:
        err.write("Mismatching passwords.")
        sys.exit(1)
    return passwd.encode('utf-8')

def generate_mac(derived_key, encrypted_private_key):
    m = keccak_256()
    m.update(derived_key[len(derived_key) >> 1:])
    m.update(encrypted_private_key)
    return m.digest()

def generate_addr(pub_key):
    m = keccak_256()
    m.update(pub_key)
    return m.hexdigest()[24:]

def decrypt(passwd=None, salt=None, n=None, r=None, p=None, dklen=None, iv=None, enc_pk=None):
    # decrypt the ase-128-ctr to have the secp256k1 private key
    #   use scrypt for key derivation
    m = 128 * r * (n + p + 2)
    dk = scrypt(passwd, salt=salt, n=n, r=r, p=p, dklen=dklen, maxmem=m)
    obj = AES.new(dk[:dklen >> 1],
                    mode=AES.MODE_CTR,
                    counter=Counter.new(128,
                                        initial_value=int.from_bytes(iv, 'big')))
    priv_key = obj.decrypt(enc_pk)
    
    # generate the mac
    mac = generate_mac(dk, enc_pk)
    return priv_key, mac

def encrypt(passwd=None, salt=None, n=None, r=None, p=None, dklen=None, iv=None, priv_key=None):
    # decrypt the ase-128-ctr to have the secp256k1 private key
    #   use scrypt for key derivation
    m = 128 * r * (n + p + 2)
    dk = scrypt(passwd, salt=salt, n=n, r=r, p=p, dklen=dklen, maxmem=m)
    obj = AES.new(dk[:dklen >> 1],
                    mode=AES.MODE_CTR,
                    counter=Counter.new(128,
                                        initial_value=int.from_bytes(iv, 'big')))
    enc_pk = obj.encrypt(priv_key)
    
    # generate the mac
    mac = generate_mac(dk, enc_pk)
    return enc_pk, mac

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Decrypt/verify the Ethereum UTC JSON keystore file')
    parser.add_argument('input', metavar='INPUT', type=str, nargs='?',
                        help='the keystore file')
    parser.add_argument('--verify-key', action='store_true', default=False)
    parser.add_argument('--show-key', action='store_true', default=False)
    parser.add_argument('--use-new-iv', action='store_true', default=False)
    parser.add_argument('--gen', action='store_true', default=False, help='generate a new wallet')
    parser.add_argument('--with-key', action='store_true', default=False, help='use the specified key')
    parser.add_argument('--light', action='store_true', default=False, help='use n = 4096 for --gen')
    parser.add_argument('--force', action='store_true', default=False, help='bypass the password check')

    args = parser.parse_args()

    if args.gen:
        if args.with_key:
            err.write('Please enter the private key (hex): ')
            hex_key = input().strip()
            if len(hex_key) == 66:
                hex_prefix = hex_key[:2]
                if hex_prefix == '0x' or hex_prefix == '0X':
                    hex_key = hex_key[2:]
            if len(hex_key) != 64:
                err.write("invalid private key hex length\n")
                sys.exit(1)
            try:
                priv_key = bytes.fromhex(hex_key)
            except ValueError:
                err.write("not a valid hex key\n")
                sys.exit(1)
            sk = SigningKey.from_string(priv_key, curve=SECP256k1)
        else:
            sk = SigningKey.generate(curve=SECP256k1)
            priv_key = sk.to_string()

        pub_key = sk.get_verifying_key().to_string()

        iv = os.urandom(16)
        salt = os.urandom(16)
        n = 1 << (12 if args.light else 18)
        r = 8
        p = 1
        passwd = getpass2()
        pwd_len = len(passwd)
        pwd_ent = entropy(passwd)
        err.write("pass length = {} bytes\n"
                "pass entropy = {}, {:.2f}%\n".format(
                    pwd_len, pwd_ent, pwd_ent / log(pwd_len, 2) * 100))
        enc_pk, mac = encrypt(passwd=passwd,
                            iv=iv, priv_key=priv_key, salt=salt, n=n, r=r, p=p, dklen=32)
        addr = generate_addr(pub_key)
        if args.show_key:
            err.write("> private key: {}\n".format(priv_key.hex()))
        err.write("> public key: {}\n".format(pub_key.hex()))
        err.write("> address: {}\n".format(addr))
        crypto = {
                'ciphertext': enc_pk.hex(),
                'cipherparams': {'iv': iv.hex()},
                'cipher': 'aes-128-ctr',
                'kdf': 'scrypt',
                'kdfparams': {'dklen': 32,
                              'salt': salt.hex(),
                              'n': n,
                              'r': r,
                              'p': p},
                'mac': mac.hex() }
        output = {'version': 3,
                  'id': str(uuid4()),
                  'address': addr,
                  'Crypto': crypto}
        sys.stdout.write(json.dumps(output))
        sys.exit(0)

    if args.input:
        with open(args.input, "r") as f:
            parsed = json.load(f)
    else:
        parsed = json.load(sys.stdin)

    c = parsed['Crypto']
    enc_pk = bytes.fromhex(c['ciphertext'])
    iv = bytes.fromhex(c['cipherparams']['iv'])
    kdf = c['kdfparams']
    salt = bytes.fromhex(kdf['salt'])
    dklen = int(kdf['dklen'])
    n = int(kdf['n'])
    r = int(kdf['r'])
    p = int(kdf['p'])
    passwd = getpass()
    
    priv_key, mac = decrypt(passwd=passwd, iv=iv, enc_pk=enc_pk, salt=salt, n=n, r=r, p=p, dklen=dklen)

    if c['mac'] == mac.hex():
        print("-- password is correct --")
    else:
        print("!! possibly WRONG password !!")
        if not args.force: sys.exit(1)

    if args.show_key:
        print("> private key: {}".format(priv_key.hex()))
    
    if args.verify_key:
        # derive public key and address from the decrypted private key
        sk = SigningKey.from_string(priv_key, curve=SECP256k1)
        pub_key = sk.get_verifying_key().to_string()
        print("> public key: {}".format(pub_key.hex()))
        addr = generate_addr(pub_key)
        print("> address: {}".format(addr))
        if parsed['address'] == addr:
            print("-- private key matches address --")
        else:
            print("!! private key does NOT match the address !!")
            if not args.force: sys.exit(1)
    
    # generate a new encrypted wallet
    if args.use_new_iv:
        iv = os.urandom(16)
    enc_pk2, mac2 = encrypt(passwd=passwd, iv=iv, priv_key=priv_key, salt=salt, n=n, r=r, p=p, dklen=32)
    parsed['id'] = str(uuid4())
    c['ciphertext'] = enc_pk2.hex()
    c['cipherparams']['iv'] = iv.hex()
    kdf['dklen'] = 32
    c['mac'] = mac2.hex()
    
    print(json.dumps(parsed))
