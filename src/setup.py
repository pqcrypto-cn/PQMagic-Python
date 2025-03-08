from setuptools import setup, Extension
from Cython.Build import cythonize

extensions = [
    Extension(
        name="pyPQMagic",
        sources=["pqmagic_wrapper.pyx", "pqmagic_kem.pyx", "pqmagic_sig.pyx"],
        libraries=["PQMagic"],   
        library_dirs=["/path/to/library"],  # 指定库文件路径
        include_dirs=["/path/to/include"],  # 指定头文件路径
    )
]

setup(
    name='PQMagic-Python',
    # version='0.1.0',
    # author='Your Name',
    # author_email='your.email@example.com',
    description='The python bindings for PQMagic https://github.com/pqcrypto-cn/PQMagic',
    ext_modules=cythonize(extensions),
    # zip_safe=False,
)