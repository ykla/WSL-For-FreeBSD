#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build the WSL-For-FreeBSD Windows host using VS Build Tools + Ninja."""

import subprocess
import sys
import os

VSBT = r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
VCVARS = os.path.join(VSBT, "VC", "Auxiliary", "Build", "vcvarsall.bat")


def main() -> int:
    script = f'''@echo off
call "{VCVARS}" x64
set CC=cl.exe
set CXX=cl.exe
set PATH=C:\\ProgramData\\chocolatey\\bin;%PATH%
set HTTP_PROXY=http://127.0.0.1:7890
set HTTPS_PROXY=http://127.0.0.1:7890
cmake --build build --config Debug 2>&1
exit /b %ERRORLEVEL%
'''
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
