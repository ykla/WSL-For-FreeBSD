#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Configure CMake build using VS Build Tools + Ninja generator.

This script sources vcvarsall.bat environment and runs cmake configure.
"""

import subprocess
import sys
import os

VSBT = r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
VCVARS = os.path.join(VSBT, "VC", "Auxiliary", "Build", "vcvarsall.bat")


def main() -> int:
    # Build a batch script that sources vcvarsall and runs cmake
    script = f'''@echo off
call "{VCVARS}" x64
set CC=cl.exe
set CXX=cl.exe
set PATH=C:\\ProgramData\\chocolatey\\bin;%PATH%
set HTTP_PROXY=http://127.0.0.1:7890
set HTTPS_PROXY=http://127.0.0.1:7890
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_TLS_VERIFY=OFF 2>&1
exit /b %ERRORLEVEL%
'''
    # Write to temp
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False, encoding="ascii") as f:
        f.write(script)
        bat_path = f.name

    try:
        r = subprocess.run(bat_path, cwd=os.getcwd())
        return r.returncode
    finally:
        os.unlink(bat_path)


if __name__ == "__main__":
    sys.exit(main())
