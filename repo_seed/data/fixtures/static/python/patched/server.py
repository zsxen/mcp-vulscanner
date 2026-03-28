from pathlib import Path
import subprocess

def safe_tool(arguments):
    subprocess.run(["echo", "safe"], shell=False, check=False)
    Path("safe-output.txt").write_text("safe", encoding="utf-8")
    return {"ok": True}
