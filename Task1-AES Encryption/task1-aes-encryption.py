import subprocess
import hashlib
from pathlib import Path
import sys

# ==== კონფიგი ====
OPENSSL = "openssl"
PASSPHRASE = "MyStrongLabPass123!"
ITER = "200000"              # PBKDF2 გამამკაცრებელი იტერაციები
HASH = "sha256"              # PBKDF2/Key-derivation digest


BASE = Path(__file__).parent
SECRET_PLAINTEXT = BASE / "secret.txt"
SECRET_ENC = BASE / "secret.enc"
SECRET_DEC = BASE / "secret.dec.txt"

def run(cmd: list[str]) -> None:

    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        print("❌ OpenSSL NotFound", file=sys.stderr)
        raise
    except subprocess.CalledProcessError as e:
        print(f"❌error exitcode={e.returncode}: {' '.join(cmd)}", file=sys.stderr)
        raise

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    # 1)  secret.txt
    SECRET_PLAINTEXT.write_text("This file contains top secret information.\n", encoding="utf-8")
    print(f"📝 Created: {SECRET_PLAINTEXT.name}")

    # 2) Encrypt with AES-128-CBC + PBKDF2 + salt
    #    openssl enc -aes-128-cbc -salt -pbkdf2 -iter 200000 -md sha256 -in secret.txt -out secret.enc -pass pass:...
    enc_cmd = [
        OPENSSL, "enc", "-aes-128-cbc",
        "-salt",
        "-pbkdf2", "-iter", ITER, "-md", HASH,
        "-in", str(SECRET_PLAINTEXT),
        "-out", str(SECRET_ENC),
        "-pass", f"pass:{PASSPHRASE}",
    ]
    run(enc_cmd)
    print(f"🔐 Encrypted -> {SECRET_ENC.name}")

    # 3) Decrypt to secret.dec.txt
    #    openssl enc -d -aes-128-cbc -pbkdf2 -iter 200000 -md sha256 -in secret.enc -out secret.dec.txt -pass pass:...
    dec_cmd = [
        OPENSSL, "enc", "-d", "-aes-128-cbc",
        "-pbkdf2", "-iter", ITER, "-md", HASH,
        "-in", str(SECRET_ENC),
        "-out", str(SECRET_DEC),
        "-pass", f"pass:{PASSPHRASE}",
    ]
    run(dec_cmd)
    print(f"🔓 Decrypted -> {SECRET_DEC.name}")

    # 4) check - (hash-ებით)
    h1 = sha256(SECRET_PLAINTEXT)
    h2 = sha256(SECRET_DEC)
    ok = (h1 == h2)
    print(f"✅ Match: {ok}  (sha256: {h1})")
    if not ok:
        print("❌ Content does not match! ", file=sys.stderr)
        sys.exit(1)

    # 5)  (Commands used)
    print("\n# Commands used (for your lab report):")
    print(f"openssl enc -aes-128-cbc -salt -pbkdf2 -iter {ITER} -md {HASH} -in secret.txt -out secret.enc -pass pass:********")
    print(f"openssl enc -d -aes-128-cbc -pbkdf2 -iter {ITER} -md {HASH} -in secret.enc -out secret.dec.txt -pass pass:********")

if __name__ == "__main__":
    main()
