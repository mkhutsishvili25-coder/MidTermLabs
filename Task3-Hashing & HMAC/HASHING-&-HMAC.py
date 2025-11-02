from pathlib import Path
import hashlib, hmac

BASE = Path(__file__).parent

DATA = BASE / "data.txt"
DATA_MOD = BASE / "data_modified.txt"
SHA_OUT = BASE / "sha256.txt"
HMAC_OUT = BASE / "hmac_sha256.txt"
HMAC_MOD_OUT = BASE / "hmac_sha256_modified.txt"

KEY = b"secretkey123"   # Task 3B-key

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def hmac_sha256_hex(key: bytes, b: bytes) -> str:
    return hmac.new(key, b, hashlib.sha256).hexdigest()

def main():
    # --- 3A: create and hash ---
    DATA.write_text("Never trust, always verify.\n", encoding="utf-8")
    print(f"📝 Created: {DATA.name}")

    m = DATA.read_bytes()
    sha = sha256_hex(m)
    SHA_OUT.write_text(sha + "\n", encoding="utf-8")
    print(f"🔢 SHA-256(data.txt) = {sha}")
    print(f"   -> saved to {SHA_OUT.name}")

    # --- 3B: HMAC SHA-256 ---
    tag = hmac_sha256_hex(KEY, m)
    HMAC_OUT.write_text(tag + "\n", encoding="utf-8")
    print(f"🔐 HMAC-SHA256(data.txt, key=secretkey123) = {tag}")
    print(f"   -> saved to {HMAC_OUT.name}")

    # --- 3C: Integrity check (change one word) ---
    DATA_MOD.write_text("Never trust, always verify!\n", encoding="utf-8")  # changed : '.' -> '!'
    mm = DATA_MOD.read_bytes()
    tag2 = hmac_sha256_hex(KEY, mm)
    HMAC_MOD_OUT.write_text(tag2 + "\n", encoding="utf-8")
    print(f"🧪 Modified file: {DATA_MOD.name}")
    print(f"🔁 HMAC-SHA256(modified) = {tag2}")
    print(f"   -> saved to {HMAC_MOD_OUT.name}")

    # compare
    changed = (tag != tag2)
    print("\n# Result:")
    print(f"HMAC changed after 1-char edit? {changed}")
    if not changed:
        print("⚠️ Unexpected: tags equal. Check that modified text truly differs.")

    # Report helper
    print("\n# Commands/Notes for report")
    print("3A) SHA-256(data.txt) written to sha256.txt")
    print("3B) HMAC(data.txt, key=secretkey123) written to hmac_sha256.txt")
    print("3C) Modified one character and recomputed HMAC -> hmac_sha256_modified.txt (must differ)")

if __name__ == "__main__":
    main()
