# PQMagic-Python
The python bindings for PQMagic https://github.com/pqcrypto-cn/PQMagic .

## Dependencies

```bash
sudo apt update
sudo apt install build-essential  # install gcc, g++, make, libc-dev, etc.
sudo apt install cmake
pip install -r requirements.txt
```

## Build from source

```bash
python setup.py build_ext --inplace
export LD_LIBRARY_PATH=./src/PQMagic/build/install/lib:$LD_LIBRARY_PATH
pip install .
```



## Run tests

```python
python tests/pqmagic_kem_tests.py # Run self test for kems.
python tests/pqmagic_sig_tests.py # Run self test for sigs.
python tests/pqmagic_test_vec.py  # Run test using test vecs for kems and sigs.
```

## Run examples

```python
python examples/pqmagic_kem_examples.py # Run a kem example.
python examples/pqmagic_sig_examples.py # Run a sig example.
```
