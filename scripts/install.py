#!/usr/bin/env python3
"""One-click bootstrapper for Windows and Linux.

Creates a virtual environment, installs dependencies, then launches the GUI.
"""

from __future__ import annotations

import os
import subprocess
import sys
import venv
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
VENV_DIR = ROOT / ".venv"


def venv_python() -> Path:
    if os.name == "nt":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def venv_console_script(name: str) -> Path:
    if os.name == "nt":
        return VENV_DIR / "Scripts" / f"{name}.exe"
    return VENV_DIR / "bin" / name


def run(command: list[str]) -> None:
    subprocess.check_call(command, cwd=str(ROOT))


def ensure_venv() -> None:
    if not VENV_DIR.exists():
        venv.EnvBuilder(with_pip=True).create(VENV_DIR)


def install_dependencies() -> None:
    python_bin = str(venv_python())
    run([python_bin, "-m", "pip", "install", "--upgrade", "pip"])
    run([python_bin, "-m", "pip", "install", "-r", str(ROOT / "requirements.txt")])
    run([python_bin, "-m", "pip", "install", "-e", str(ROOT)])


def launch_app() -> int:
    launcher = venv_console_script("network-recon")
    process = subprocess.run([str(launcher)], cwd=str(ROOT))
    return process.returncode


def main() -> int:
    ensure_venv()
    install_dependencies()
    return launch_app()


if __name__ == "__main__":
    raise SystemExit(main())
