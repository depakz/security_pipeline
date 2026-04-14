import subprocess
import json
import shutil
import re

OUTPUT_FILE = "output/naabu.json"


def validate_target(target):
    pattern = r"^([a-zA-Z0-9.-]+)$"
    if not re.match(pattern, target):
        raise ValueError("Invalid target format")
    return target


def check_naabu_installed():
    if shutil.which("naabu") is None:
        raise EnvironmentError("naabu is not installed or not in PATH")


def run_naabu(target):
    try:
        validate_target(target)
        check_naabu_installed()

        cmd = [
            "naabu",
            "-host", target,
            "-json",
            "-silent"
        ]

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        stdout, stderr = process.communicate(timeout=60)

        if process.returncode != 0:
            raise RuntimeError(stderr.strip())

        if not stdout.strip():
            raise ValueError("Empty Naabu output")

        open_ports = []
        seen = set()

        for line in stdout.strip().split("\n"):
            try:
                entry = json.loads(line)
                port = entry.get("port")
                host = entry.get("host")

                if port and (host, port) not in seen:
                    seen.add((host, port))
                    open_ports.append({
                        "port": int(port),
                        "service": "",      # naabu does not provide service info
                        "product": "",
                        "version": ""
                    })
            except json.JSONDecodeError:
                continue

        data = {
            "target": target,
            "open_ports": open_ports
        }

    except subprocess.TimeoutExpired:
        data = {"error": "Naabu scan timed out"}

    except Exception as e:
        data = {"error": str(e)}

    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=4)

    return OUTPUT_FILE