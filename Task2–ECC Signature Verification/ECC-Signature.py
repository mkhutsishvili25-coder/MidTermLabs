import subprocess
from pathlib import Path
import sys


OPENSSL = "openssl"

BASE = Path(__file__).parent
MSG = BASE / "ecc.txt"
PRIV = BASE / "ecc_private.pem"
PUB = BASE / "ecc_public.pem"
SIG = BASE / "ecc.sig"        # DER (ASN.1) ხელმოწერა
SIG_B64 = BASE / "ecc.sig.b64"

def run(cmd: list[str], check=True, capture=False):
    try:
        if capture:
            return subprocess.run(cmd, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        else:
            subprocess.run(cmd, check=check)
    except FileNotFoundError:
        print("❌ OpenSSL path error", file=sys.stderr)
        raise
    except subprocess.CalledProcessError as e:
        print(f"❌ error: {' '.join(cmd)}\n{e}", file=sys.stderr)
        raise

def main():
    # 2A-1) prime256v1  ECC private key
    run([OPENSSL, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(PRIV)])
    print(f"🔐 Generated private key → {PRIV.name}")

    # 2A-2) public key PEM
    run([OPENSSL, "ec", "-in", str(PRIV), "-pubout", "-out", str(PUB)])
    print(f"🔓 Exported public key → {PUB.name}")


    # 2B-1) მესიჯი
    MSG.write_text("Elliptic Curves are efficient.\n", encoding="utf-8")
    print(f"📝 Created message → {MSG.name}")

    # 2B-2) ხელმოწერა (SHA-256 + ECDSA)
    run([OPENSSL, "dgst", "-sha256", "-sign", str(PRIV), "-out", str(SIG), str(MSG)])
    print(f"✍️  Signed message → {SIG.name}")


    run([OPENSSL, "base64", "-in", str(SIG), "-out", str(SIG_B64)])
    print(f"📄 Signature (Base64) → {SIG_B64.name}")

    # 2B-3) ვერიფიკაცია public key-ით
    res = run([OPENSSL, "dgst", "-sha256", "-verify", str(PUB), "-signature", str(SIG), str(MSG)], capture=True)
    print("\n# Verification output:")
    print(res.stdout.strip())


    if "Verified OK" in res.stdout:
        print("✅ ECC signature verification PASSED")
        sys.exit(0)
    else:
        print("❌ ECC signature verification FAILED", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
