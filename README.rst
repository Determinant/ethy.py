ethy.py
-------

This little script offers decryption and verification of the existing
Ethereum wallets, as well as generation of a new wallet. You can use any
utf-8 string as the password, which could provide with better security
against the brute-force attack.

Use at your own risk.

Feature
-------

- Decrypt the UTC JSON wallet and see the private key
- Run secp256k1 to make sure the private key is intact and really corresponds to the wallet address
- Generate a wallet

Dependencies
------------

- pycrypto
- pysha3
- ecdsa

Install
-------

.. code-block:: bash

    git clone https://github.com/Determinant/ethy.py
    pip3 install --user ethy.py/

Example
-------

.. code-block:: bash

    ethy.py --verify-key mywallet.json # unlock the wallet and verify whether the
                                       # encrypted private key matches the address
    ethy.py --show-key mywallet.json   # reveal the private key (secp256k1)

    ethy.py --gen > mywallet.json             # generate a regular wallet (1s)
    ethy.py --gen --light > mywallet.json     # generate a wallet (fast)
    ethy.py --gen --with-key > mywallet.json  # generate a wallet with the given private key
