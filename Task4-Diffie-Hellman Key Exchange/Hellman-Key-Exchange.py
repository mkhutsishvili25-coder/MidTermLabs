import secrets, hashlib
from pathlib import Path

# === RFC 3526 Group 14 (2048-bit MODP) - safe prime

P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
    "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"
)
p = int(P_HEX, 16)
g = 2

BASE = Path(__file__).parent
(ALICE_PUB := BASE / "alice_public.txt")
(BOB_PUB := BASE / "bob_public.txt")
(ALICE_KEY := BASE / "shared_key_alice.hex")
(BOB_KEY := BASE / "shared_key_bob.hex")

def kdf_sha256(shared_int: int) -> bytes:
    """Simple KDF: SHA-256 over big-endian integer -> 32-byte key."""
    s_bytes = shared_int.to_bytes((shared_int.bit_length() + 7) // 8, "big")
    return hashlib.sha256(s_bytes).digest()

def main():
    # Private exponents (256-bit random enough for the lab)
    a = secrets.randbits(256)
    b = secrets.randbits(256)

    # Public keys A = g^a mod p, B = g^b mod p
    A = pow(g, a, p)
    B = pow(g, b, p)

    # Shared secrets (should be identical): s = B^a mod p = A^b mod p
    s_alice = pow(B, a, p)
    s_bob   = pow(A, b, p)

    # Derive 32-byte symmetric key with SHA-256
    k_alice = kdf_sha256(s_alice)
    k_bob   = kdf_sha256(s_bob)

    # Print step-by-step
    print("=== Diffie–Hellman (RFC3526 Group 14) ===")
    print(f"Generator g: {g}")
    print(f"Prime p (bits): {p.bit_length()}")
    print("\n-- Public keys --")
    print(f"Alice public (A) = g^a mod p =\n{A}\n")
    print(f"Bob   public (B) = g^b mod p =\n{B}\n")

    print("-- Shared secrets --")
    print(f"Alice s = B^a mod p =\n{s_alice}\n")
    print(f"Bob   s = A^b mod p =\n{s_bob}\n")
    print(f"Identical? {s_alice == s_bob}")

    print("\n-- Derived 32-byte key (SHA-256) --")
    print(f"Alice key: {k_alice.hex()}")
    print(f"Bob   key: {k_bob.hex()}")
    print(f"Keys identical? {k_alice == k_bob}")

    # Save artifacts
    ALICE_PUB.write_text(str(A), encoding="utf-8")
    BOB_PUB.write_text(str(B), encoding="utf-8")
    ALICE_KEY.write_text(k_alice.hex() + "\n", encoding="utf-8")
    BOB_KEY.write_text(k_bob.hex() + "\n", encoding="utf-8")

    print("\nFiles written:")
    print(f"- {ALICE_PUB.name} (Alice public)")
    print(f"- {BOB_PUB.name}   (Bob public)")
    print(f"- {ALICE_KEY.name} (Alice derived key, hex)")
    print(f"- {BOB_KEY.name}   (Bob derived key, hex)")

if __name__ == "__main__":
    main()
