import os
import sys
import subprocess
import shutil
from setuptools import setup, Extension, find_packages
from setuptools.command.build_ext import build_ext as build_ext_orig
from Cython.Build import cythonize

with open("README.md", "r", encoding="utf-8") as fh:
    ld = fh.read()

compile_args = {
    'linux': ['-O3'],
    'darwin': ['-O3', '-mmacosx-version-min=10.9'],
    'win32': ['-O2', '-DMS_WIN64']
}
link_args = {
    'linux': [],
    'darwin': ['-mmacosx-version-min=10.9'],
    'win32': []
}

platform = sys.platform

class build_ext(build_ext_orig):
    def finalize_options(self):
        # 强制用 mingw
        if platform == "win32":
            self.compiler = "mingw32"
        super().finalize_options()
    
    def run(self):
        self.compile_pqmagic()
        super().run()

    def _has_command(self, cmd):
        return shutil.which(cmd) is not None

    # Function to compile and install the PQMagic C library
    def compile_pqmagic(self):
        # platform = sys.platform         
        build_dir = os.path.join("pqmagic", "PQMagic", "build")
        install_dir = os.path.abspath(os.path.join(build_dir, "install"))  # Custom install directory
        os.makedirs(build_dir, exist_ok=True)
        
        # Check for CMake
        if not self._has_command("cmake"):
            sys.stderr.write("Error: CMake is required to build PQMagic. Please install it first.\n")
            sys.exit(1)
        
        # Common CMake options
        common_cmake_opts = [
            "..",
            "-DUSE_SHAKE=ON",
            f"-DCMAKE_INSTALL_PREFIX={install_dir}",
            "-DENABLE_TEST=OFF",
            "-DENABLE_BENCH=OFF",
            "-DCMAKE_C_COMPILER=gcc",
            "-DCMAKE_CXX_COMPILER=g++"
        ]

        if platform.startswith("linux") or platform == "darwin":
            cmake_cmd = ["cmake"] + common_cmake_opts
            install_cmd = ["make", "install", f"-j {os.cpu_count() - 2}"]
        elif platform == "win32":
            # Check for CMake and Ninja
            if self._has_command("ninja"):
               cmake_cmd = ["cmake", "-G", "Ninja"] + common_cmake_opts
               install_cmd = ["ninja", "install", f"-j {os.cpu_count() - 2}"]
            elif self._has_command("mingw32-make"):
                cmake_cmd = ["cmake", "-G", "MinGW Makefiles"] + common_cmake_opts
                install_cmd = ["mingw32-make", "install", f"-j {os.cpu_count() - 2}"]
            else:
                print("Error: Currently PQMagic-Python only supports ninja and mingw32-make.")
                sys.exit(1)
        else:
            print(f"Unsupported platform: {platform}")
            sys.exit(1)

        try:
            subprocess.check_call(cmake_cmd, cwd=build_dir)
            subprocess.check_call(install_cmd, cwd=build_dir)

        except FileNotFoundError as e:
            print(f"Build tool not found: {e}\n")
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            print(f"Error during PQMagic compilation: {e}\n")
            sys.exit(1)

        try:
            # Copy the compiled library to the package directory
            if platform.startswith('linux'):
                lib_files = ["libpqmagic.so", "libpqmagic_std.so"]
            elif platform == 'darwin':
                lib_files = ["libpqmagic.dylib", "libpqmagic_std.dylib"]
            elif platform == 'win32':
                lib_files = ["libpqmagic_std.dll"]
            build_lib_pqmagic = os.path.join(self.build_lib, "pqmagic")
            os.makedirs(build_lib_pqmagic, exist_ok=True)

            for lib_file in lib_files:
                src = os.path.join(install_dir, "lib", lib_file)
                dst = os.path.join(build_lib_pqmagic, lib_file)
                shutil.copy2(src, dst)
                print(f"Copied {lib_file} to {dst}")         
            
        except FileNotFoundError as e:
            print(f"Error copying library: {e}\n")
            sys.exit(1)

#--- Set rpath for extension ---
# The rpath must point to where the .so or .dylib will be at runtime, relative to the extension.
extra_link_args = link_args.get(platform, [])
if platform.startswith('linux'):
    extra_link_args.append("-Wl,-rpath,$ORIGIN")
elif platform == 'darwin':
    extra_link_args.append("-Wl,-rpath,@loader_path")

extensions = [
    Extension(
        name="pqmagic.pqmagic",
        sources=["pqmagic/pqmagic.pyx"],
        libraries=["pqmagic_std"],  # Link the compiled PQMagic-C library
        library_dirs=["pqmagic/PQMagic/build/install/lib"],
        include_dirs=["pqmagic/PQMagic/build/install/include"],
        extra_compile_args=compile_args.get(platform, []),
        extra_link_args=extra_link_args
    )
]

setup(
    name='pqmagic',
    version='1.0.5',
    install_requires=['Cython', 'wheel', 'setuptools'],
    homepage='https://pqcrypto.dev',
    description='The python bindings for PQMagic https://github.com/pqcrypto-cn/PQMagic',
    long_description=ld,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    ext_modules=cythonize(extensions),
    package_data={
        "pqmagic": [
            "*.pyx", 
            "*.pxd",
            "*.so",
            "*.dylib",
            "*.dll",
        ]
    },
    include_package_data=True,
    cmdclass={'build_ext': build_ext},
)