# PQMagic-python

 The python bindings for PQMagic https://github.com/pqcrypto-cn/PQMagic . [PQMagic](https://pqcrypto.dev/) (Post-Quantum Magic) is the first **high-performance post-quantum cryptographic algorithm library** that supports both the [FIPS 203 204 205](https://csrc.nist.gov/news/2024/postquantum-cryptography-fips-approved) standards in China, and it supports the higher performance PQC algorithms designed by us: **Aigis-Enc、Aigis-Sig** ([PKC 2020]((https://eprint.iacr.org/2019/510))) and **SPHINCS-Alpha** ([CRYPTO 2023](https://eprint.iacr.org/2022/059)). PQMagic has implemented cryptographic modifications to the **Hash Function Components** of all algorithms, better aligning with Chinese standards while seamlessly integrating with international standards. This project aims to help developers use the high-performance PQC algorithms in python for more convenience and flexibility.

## Algorithms Support
PQMagic-python supports the standard algorithms selected by NIST, as well as some self-developed algorithms. The current entirety is shown as follows.

For KEM algorithms, it supports:  
`ML_KEM_512`, `ML_KEM_768`, `ML_KEM_1024`, `KYBER_512`, `KYBER_768`, `KYBER_1024`, `AIGIS_ENC_1`, `AIGIS_ENC_2`, `AIGIS_ENC_3`, `AIGIS_ENC_4`.

For SIG algorithms, it supports:  
`SLH_DSA_SHA2_128f`, `SLH_DSA_SHA2_128s`, `SLH_DSA_SHA2_192f`, `SLH_DSA_SHA2_192s`, `SLH_DSA_SHA2_256f`, `SLH_DSA_SHA2_256s`, 
`SLH_DSA_SHAKE_128f`, `SLH_DSA_SHAKE_128s`, `SLH_DSA_SHAKE_192f`, `SLH_DSA_SHAKE_192s`, `SLH_DSA_SHAKE_256f`, `SLH_DSA_SHAKE_256s`, 
`SLH_DSA_SM3_128f`, `SLH_DSA_SM3_128s`, `DILITHIUM_2`, `DILITHIUM_3`, `DILITHIUM_5`, `SPHINCS_Alpha_SHA2_128f`, `SPHINCS_Alpha_SHA2_128s`, `SPHINCS_Alpha_SHA2_192f`, `SPHINCS_Alpha_SHA2_192s`, `SPHINCS_Alpha_SHA2_256f`, `SPHINCS_Alpha_SHA2_256s`, 
`SPHINCS_Alpha_SHAKE_128f`, `SPHINCS_Alpha_SHAKE_128s`, `SPHINCS_Alpha_SHAKE_192f`, `SPHINCS_Alpha_SHAKE_192s`,  `SPHINCS_Alpha_SHAKE_256f`, `SPHINCS_Alpha_SHAKE_256s`, `SPHINCS_Alpha_SM3_128f`, `SPHINCS_Alpha_SM3_128s`.  

## Launch
### From PyPI
For Windows, we have built several wheels (x64, python>=3.10). 
```powershell
pip install pqmagic
```

For Linux/MacOS, currently we only allow building from source distribution. So please first install cmake and build tools for source code compilation:
```bash
sudo apt install cmake build-essential # for Linux
brew install cmake make # for MacOS
```
Then install from pip:
```sh
pip install -v pqmagic
```

### From Source Code
You can also build and install from scratch:
#### Dependencies

```bash
sudo apt update
sudo apt install build-essential  # install gcc, g++, make, libc-dev, etc.
sudo apt install cmake
pip install -r requirements.txt
```

#### Build from source

```bash
git clone --recurse-submodules https://github.com/pqcrypto-cn/PQMagic-Python.git
python setup.py build_ext --inplace
export LD_LIBRARY_PATH=./pqmagic/PQMagic/build/install/lib:$LD_LIBRARY_PATH
pip install .
```


## Usage
We have encapsulated all the algorithms to classes `Kem` and `Sig`. All the cryptographic data is presented with type `bytes`.

For KEMs, a specific algorithm object can be instantiated from the algorithm name, and is attached to a pair of keys `[pk, sk]`, which can be generated (or updated) with function `keypair()`. For correct instantiation, you may need to check the algorithm names [here](#algorithms-support). When performing keys encapsulation and decapsulation on an object, we allow using a new key or the object's attached key. Here is an example of `ML_KEM_512`.

```py
# KEM object instantiation
kem = Kem("ML_KEM_512")

# generate a key pair (or update the attached key pair)
pk, sk = kem.keypair()

# encapsulation
ciphertext, shared_secret_enc = kem.encaps(pk) # with a specified pk
ciphertext, shared_secret_enc = kem.encaps() # with the attached pk

# decapsulation
shared_secret_dec = kem.decaps(ciphertext, sk) # with a specified sk
shared_secret_dec = kem.decaps(ciphertext)# with the attached sk
```

For Sigs, similarly, a specific algorithm object can be instantiated from the algorithm name, and is attached to a pair of keys `[pk, sk]`. For correct instantiation, you may need to check the algorithm names [here](#algorithms-support). Note that some of the algorithms need `context` when signing/verifying, while others do not. When signing/verifying with specified keys, if the context is empty, please explicitly provide the key as the last parameter. We have two modes of signature and verification for each algorithm: `sign-verify` and `sign_pack-open`. The former just produces the siganature, while the latter packs the signature along with the message and the context. Here is an example of `ML_DSA_44`.

```py
message = b"This is a test message."
context = b"Test context."

# Sig object instantiation
sig = Sig("ML_DSA_44")

# generate key pair (or update the object's attached key pair)
pk, sk = sig.keypair()

# sign message
signature = sig.sign(message, context, sk) 
# or sig.sign(message, context), but note that the key should be explicitly provided if the context is empty: sign(m, sk = b'xxxx')

# verify signature: True or False
result = sig.verify(signature, message, context, pk)
# or sig.verify(signature, message, context), but note that the key should be explicitly provided if the context is empty: verify(sig, m, pk = b'xxxx')

# sign and pack message
signed_message = sig.sign_pack(message, context, sk)
# or sig.sign_pack(message, context), but note that the key should be explicitly provided if the context is empty: sign_pack(m, sk = b'xxxx')

# open and verify signed message: True or False
result = sig.open(message, signed_message, context, pk)
# or sig.open(message, signed_message, context), but note that the key should be provided if the context is empty: open(m, sm, pk = b'xxxx')
```

For more details on usage, check [examples](examples). If you have any advice or issue, please contact us on [Github](https://github.com/pqcrypto-cn/PQMagic-Python).

### Run tests

```python
python tests/pypqmagic_kem_tests.py # Run self test for kems.
python tests/pypqmagic_sig_tests.py # Run self test for sigs.
python tests/pypqmagic_test_vec.py  # Run test using test vecs for kems and sigs.
```

### Run examples

```python
python examples/pqmagic_kem_examples.py # Run a kem example.
python examples/pqmagic_sig_examples.py # Run a sig example.
```