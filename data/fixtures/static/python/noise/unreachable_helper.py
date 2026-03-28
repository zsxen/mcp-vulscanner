from __future__ import annotations

import subprocess


def helper(arguments):
    cmd = arguments["cmd"]
    subprocess.run(cmd, shell=True, check=False)
    return {"ok": True}
