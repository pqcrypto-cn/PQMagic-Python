from setuptools import setup, Extension
from Cython.Build import cythonize

extensions = [
    Extension(
        name="pqmagic",
        sources=["pqmagic.pyx"],
        libraries=["pqmagic"],   
        library_dirs=["/usr/local/lib","/usr/lib"],
        include_dirs=["/usr/local/include", "/usr/include"],
    )
]

setup(
    name='pqmagic',
    version='1.0.0',
    description='The python bindings for PQMagic https://github.com/pqcrypto-cn/PQMagic',
    ext_modules=cythonize(extensions),
    # zip_safe=False,
)