from setuptools import setup

setup(name='ethy.py',
      version='0.2',
      description='Decryption/verification/generation of Ethereum/BTC wallets',
      url='http://github.com/Determinant/ethy.py',
      author='Ted Yin',
      author_email='tederminant@gmail.com',
      license='MIT',
      scripts=['ethy.py'],
      install_requires=[
          'pycrypto',
          'pysha3',
          'ecdsa',
          'base58'
          ])
