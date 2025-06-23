import tempfile
import base64
import binascii
import os
import sys


def env_or_fail(name):
    """Get an environment variable or exit with an error."""
    value = os.environ.get(name)
    if value is None:
        print(f"Missing environment variable: {name}", file=sys.stderr)
        sys.exit(1)
    return value


def main():
    b64 = ""
    try:
        b64 += input("Base64 encoded file, end with empty line:\n").strip()
    except EOFError:
        print("Unexpected EOF, exiting...", flush=True)
        return
    while True:
        try:
            line = input()
        except EOFError:
            break
        if not line.strip():
            break
        b64 += line.strip()

    try:
        js = base64.b64decode(b64)
    except binascii.Error:
        print("Invalid input", flush=True)
        return

    if len(js) >= 100_000:
        print("Too long input", flush=True)
        return

    with tempfile.NamedTemporaryFile(suffix=".html") as f:
        f.write(js)
        f.seek(0)

        try:
            print("Starting Ladybird...", flush=True)
            os.execv(
                "./bin/Ladybird",
                [
                    "Ladybird",
                    "--force-new-process",
                    f.name,
                ],
            )
        except Exception as e:
            print(e, flush=True)


if __name__ == "__main__":
    main()
