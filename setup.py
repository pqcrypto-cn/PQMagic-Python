import os
import sys
import subprocess
from setuptools import setup, Extension
from Cython.Build import cythonize

with open("README.md", "r", encoding="utf-8") as fh:
    ld = fh.read()

compile_args = {
    'linux': ['-std=c++11', '-O3'],
    'darwin': ['-std=c++11', '-O3', '-mmacosx-version-min=10.9'],
    'win32': ['/O2', '/EHsc']
}
link_args = {
    'darwin': ['-mmacosx-version-min=10.9']
}

platform = sys.platform
# Function to compile and install the PQMagic C library
def compile_pqmagic():
    build_dir = os.path.join("src", "PQMagic", "build")
    install_dir = os.path.abspath(os.path.join(build_dir, "install"))  # Custom install directory
    os.makedirs(build_dir, exist_ok=True)
    cmake_cmd = ["cmake", "..", f"-DCMAKE_INSTALL_PREFIX={install_dir}", "-DUSE_SHAKE=ON"]
    # make_cmd = ["make"]
    install_cmd = ["make", "install", "-j"]
    if platform == "win32":
        cmake_cmd = ["cmake", "..", "-G", "MinGW Makefiles", f"-DCMAKE_INSTALL_PREFIX={install_dir}"]
        # make_cmd = ["mingw32-make"]
        install_cmd = ["mingw32-make", "install"]
    try:
        subprocess.check_call(cmake_cmd, cwd=build_dir)
        # subprocess.check_call(make_cmd, cwd=build_dir)
        subprocess.check_call(install_cmd, cwd=build_dir)
    except subprocess.CalledProcessError as e:
        print(f"Error during PQMagic compilation: {e}")
        sys.exit(1)

# Compile the C library before proceeding
compile_pqmagic()

extensions = [
    Extension(
        name="pqmagic",
        sources=["src/pqmagic.pyx"],
        libraries=["pqmagic","pqmagic_std"],  # Link the compiled PQMagic library
        library_dirs=["src/PQMagic/build/install/lib"],
        include_dirs=["src/PQMagic/build/install/include"],
        extra_compile_args=compile_args.get(platform, []),
        extra_link_args=link_args.get(platform, [])
    )
]

setup(
    name='pqmagic',
    version='1.0.0',
    requires=['Cython'],
    install_requires=['Cython'],
    description='The python bindings for PQMagic https://github.com/pqcrypto-cn/PQMagic',
    long_description=ld,
    long_description_content_type="text/markdown",
    ext_modules=cythonize(extensions),
    options={"bdist_wheel": {"universal": True}},
)