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

import os
import sys
import json
import argparse
import hashlib
from uuid import uuid4
from getpass import getpass as _getpass
from collections import Counter as Histogram
from math import log
from Crypto.Cipher import AES
from Crypto.Util import Counter
from sha3 import keccak_256
from ecdsa import SigningKey, SECP256k1
from base58 import b58encode

err = sys.stderr


def entropy(data):
    n = len(data)
    return sum([-p * log(p, 2) for p in
                [c / n for _, c in Histogram(data).items()]])


def getpass():
    return _getpass().encode('utf-8')


def getpass2():
    passwd = _getpass('Enter your wallet password (utf-8): ')
    rpasswd = _getpass('Repeat the password: ')
    if passwd != rpasswd:
        err.write("Mismatching passwords.")
        sys.exit(1)
    return passwd.encode('utf-8')


def getseed():
    passwd = _getpass('Enter some arbitrary seed (utf-8): ')
    return passwd.encode('utf-8')


def generate_mac(derived_key, encrypted_private_key):
    m = keccak_256()
    m.update(derived_key[len(derived_key) >> 1:])
    m.update(encrypted_private_key)
    return m.digest()


def sha256(data):
    h = hashlib.sha256()
    h.update(data)
    return h.digest()


def ripemd160(data):
    h = hashlib.new('ripemd160')
    h.update(data)
    return h.digest()


class KeyGen:
    @classmethod
    def generate(cls):
        kg = KeyGen()
        kg.sk = SigningKey.generate(curve=SECP256k1)
        kg.pk = kg.sk.get_verifying_key()
        return kg

    @classmethod
    def from_string(cls, priv_key):
        kg = KeyGen()
        kg.sk = SigningKey.from_string(priv_key, curve=SECP256k1)
        kg.pk = kg.sk.get_verifying_key()
        return kg

    def get_pubkey_hex(self):
        return self.pk.to_string().hex()

    def get_privkey(self):
        return self.sk.to_string()

    def get_privkey_hex(self):
        return self.get_privkey().hex()

    def get_privkey_btc(self):
        priv_key = b'\x80' + self.sk.to_string()
        checksum = sha256(sha256(priv_key))[:4]
        return b58encode(priv_key + checksum).decode("utf-8")

    def get_eth_addr(self):
        pub_key = self.pk.to_string()
        m = keccak_256()
        m.update(pub_key)
        return m.hexdigest()[24:]

    def get_btc_addr(self):
        pub_key = b'\x04' + self.pk.to_string()
        h = b'\x00' + ripemd160(sha256(pub_key))
        checksum = sha256(sha256(h))[:4]
        h += checksum
        return b58encode(h).decode("utf-8")


def decrypt(passwd=None, salt=None,
            n=None, r=None, p=None, dklen=None, iv=None, enc_pk=None):
    # decrypt the ase-128-ctr to have the secp256k1 private key
    #   use scrypt for key derivation
    m = 128 * r * (n + p + 2)
    dk = hashlib.scrypt(passwd, salt=salt,
                        n=n, r=r, p=p, dklen=dklen, maxmem=m)
    obj = AES.new(dk[:dklen >> 1],
                  mode=AES.MODE_CTR,
                  counter=Counter.new(128,
                                      initial_value=int.from_bytes(iv, 'big')))
    priv_key = obj.decrypt(enc_pk)
    # generate the mac
    mac = generate_mac(dk, enc_pk)
    return priv_key, mac


def encrypt(passwd=None, salt=None,
            n=None, r=None, p=None, dklen=None, iv=None, priv_key=None):
    # decrypt the ase-128-ctr to have the secp256k1 private key
    #   use scrypt for key derivation
    m = 128 * r * (n + p + 2)
    dk = hashlib.scrypt(passwd, salt=salt,
                        n=n, r=r, p=p, dklen=dklen, maxmem=m)
    obj = AES.new(dk[:dklen >> 1],
                  mode=AES.MODE_CTR,
                  counter=Counter.new(128,
                                      initial_value=int.from_bytes(iv, 'big')))
    enc_pk = obj.encrypt(priv_key)
    # generate the mac
    mac = generate_mac(dk, enc_pk)
    return enc_pk, mac


def show_entropy(bytes, prompt="pass"):
    pwd_len = len(bytes)
    pwd_ent = entropy(bytes)
    if pwd_len < 2:
        err.write("{} is too short!\n".format(prompt))
        sys.exit(1)
    err.write("{0} length = {1} bytes\n"
              "{0} entropy = {2}, {3:.2f}%\n".format(
                    prompt,
                    pwd_len, pwd_ent, pwd_ent / log(pwd_len, 2) * 100))


def save_to_file(kg, passwd, fs):
    iv = os.urandom(16)
    salt = os.urandom(16)
    if args.light:
        n = 1 << 12
        p = 6
    else:
        n = 1 << 18
        p = 1
    r = 8
    show_entropy(passwd)
    enc_pk, mac = encrypt(
            passwd=passwd,
            iv=iv, priv_key=kg.get_privkey(), salt=salt,
            n=n, r=r, p=p, dklen=32)
    addr = kg.get_eth_addr()
    if args.show_key:
        err.write("> private key: {}\n".format(kg.get_privkey_hex()))
        err.write("> private key (btc): {}\n".format(kg.get_privkey_btc()))
    err.write("> public key: {}\n".format(kg.get_pubkey_hex()))
    err.write("> address: {}\n".format(addr))
    err.write("> address (btc): {}\n".format(kg.get_btc_addr()))
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
            'mac': mac.hex()}
    output = {'version': 3,
              'id': str(uuid4()),
              'address': addr,
              'Crypto': crypto}
    sys.stdout.write("{}\n".format(json.dumps(output)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Decrypt/verify the Ethereum UTC JSON keystore file')
    parser.add_argument('input', metavar='INPUT', type=str, nargs='?',
                        help='the keystore file')
    parser.add_argument('--verify-key', action='store_true', default=False)
    parser.add_argument('--show-key', action='store_true', default=False)
    parser.add_argument('--use-new-iv', action='store_true', default=False)
    parser.add_argument('--gen', action='store_true', default=False, help='generate a new wallet')
    parser.add_argument('--gen-batch', action='store', default=None, type=int, help='generate some wallets')
    parser.add_argument('--with-key', action='store_true', default=False, help='use the specified key')
    parser.add_argument('--pass-stdin', action='store_true', default=False, help='read the password from stdin')
    parser.add_argument('--light', action='store_true', default=False, help='use n = 4096 for --gen')
    parser.add_argument('--force', action='store_true', default=False, help='bypass the password check')

    args = parser.parse_args()

    if args.gen_batch:
        if args.gen_batch < 1:
            err.write("invalid argument")
            sys.exit(1)
        seed = getseed()
        show_entropy(seed, "seed")
        h = keccak_256()
        h.update(seed)
        h2 = keccak_256()
        h2.update(h.digest())
        wid = h2.hexdigest()[32:]
        for i in range(args.gen_batch):
            h = keccak_256()
            h.update(seed)
            h.update("\0".encode("utf-8"))
            h.update(str(i).encode("utf-8"))
            password = b58encode(h.digest())

            kg = KeyGen.generate()
            wname = "wallet-{}-{:03d}".format(wid, i)
            f = open("{}.json".format(wname), "w")
            save_to_file(kg, password, f)
            sys.stdout.write("password({}) = {}\n".format(
                wname, password.decode("ascii")))
        sys.exit(0)
    elif args.gen:
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
            kg = KeyGen.from_string(priv_key)
        else:
            kg = KeyGen.generate()
        save_to_file(kg, getpass2(), sys.stdout)
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
    if args.pass_stdin:
        passwd = sys.stdin.readline()[:-1].encode('utf-8')
    else:
        passwd = getpass()
    priv_key, mac = decrypt(passwd=passwd, iv=iv, enc_pk=enc_pk, salt=salt,
                            n=n, r=r, p=p, dklen=dklen)

    if c['mac'] == mac.hex():
        err.write("-- password is correct --\n")
    else:
        err.write("!! possibly WRONG password !!\n")
        if not args.force:
            sys.exit(1)

    if args.show_key:
        kg = KeyGen.from_string(priv_key)
        err.write("> private key: {}\n".format(kg.get_privkey_hex()))
        err.write("> private key (btc): {}\n".format(kg.get_privkey_btc()))
    if args.verify_key:
        # derive public key and address from the decrypted private key
        kg = KeyGen.from_string(priv_key)
        err.write("> public key: {}\n".format(kg.get_pubkey_hex()))
        addr = kg.get_eth_addr()
        err.write("> address: {}\n".format(addr))
        err.write("> address (btc): {}\n".format(kg.get_btc_addr()))
        if parsed['address'] == addr:
            err.write("-- private key matches address --\n")
        else:
            err.write("!! private key does NOT match the address !!\n")
            if not args.force:
                sys.exit(1)
    # generate a new encrypted wallet
    if args.use_new_iv:
        iv = os.urandom(16)
    enc_pk2, mac2 = encrypt(
            passwd=passwd, iv=iv, priv_key=priv_key, salt=salt,
            n=n, r=r, p=p, dklen=32)
    parsed['id'] = str(uuid4())
    c['ciphertext'] = enc_pk2.hex()
    c['cipherparams']['iv'] = iv.hex()
    kdf['dklen'] = 32
    c['mac'] = mac2.hex()
    sys.stdout.write("{}\n".format(json.dumps(parsed)))
