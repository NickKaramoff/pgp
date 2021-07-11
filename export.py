#!/usr/bin/env python3

"""This script exports public keys for every saved secret key. Expired and revoked keys
will be saved to the respective folders. A symlink will be created for the default key.
"""
import re
import sys
from pathlib import Path
from shutil import copy2
from subprocess import PIPE, Popen
from typing import Optional

if sys.version_info < (3, 9):
    raise RuntimeError("Only Python 3.9 and newer is supported")

line_re = re.compile(r"^sec([>#]\s{2}|\s{3})[\w\d]+\/0x(?P<keyid>[0-9A-F]{16})")


def find_keys() -> list[tuple[str, Optional[str]], bool]:
    with Popen(
        ["gpg", "--list-secret-keys", "--keyid-format", "0xlong"],
        stdout=PIPE,
        encoding="utf-8",
    ) as p:
        output = p.stdout.read()

        key_ids = []

        for line in output.splitlines():
            if not line.startswith("sec"):
                continue

            match = line_re.match(line)
            if match is None:
                continue

            key_id = match.group("keyid")
            if key_id is None:
                continue

            if "[expired" in line or "[revoked" in line:
                status = "old"
            else:
                status = None

            default = line.startswith("sec>")

            key_ids.append((key_id, status, default))

        return key_ids


def export_key(key_id: str, status: Optional[str], default: bool) -> None:
    with Popen(
        ["gpg", "--armor", "--export", key_id],
        stdout=PIPE,
        encoding="utf-8",
    ) as p:
        key = p.stdout.read()

        path = Path.cwd()

        if status is not None:
            path /= status

        path.mkdir(parents=True, exist_ok=True)

        path /= f"{key_id}.asc"

        path.write_text(key)

        if default:
            sym_path = path.with_stem("primary")
            sym_path.unlink(missing_ok=True)
            copy2(path, sym_path)


if __name__ == "__main__":
    for key, status, default in find_keys():
        export_key(key, status, default)
