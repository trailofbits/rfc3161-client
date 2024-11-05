import sys
import os
from pathlib import Path

import dlltracer


def add_dll():
    if openssl_dir := os.environ.get("OPENSSL_DIR"):
        os.add_dll_directory(openssl_dir)
        print(f"Dlls : {list(Path(openssl_dir).glob('*.dll'))}")

    if pyo3_python := os.environ.get("PYO3_PYTHON"):
        python_dir = Path(pyo3_python).parent
        print(f"Dlls ({python_dir}) : {list(Path(python_dir).glob('*.dll'))}")
        os.add_dll_directory(python_dir.as_posix())


with dlltracer.Trace(out=sys.stdout):
    import rfc3161_client