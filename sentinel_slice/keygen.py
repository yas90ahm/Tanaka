import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

PRIVATE_KEY_PATH = "sentinel_slice/keys/cashier_ed25519_private.pem"
PUBLIC_KEY_PATH = "sentinel_slice/keys/cashier_ed25519_public.pem"


def generate_keypair(keys_dir) -> tuple[str, str]:
    """Generate one Ed25519 keypair and write both PEMs into keys_dir.

    Returns the tuple (private_path, public_path) of the two files written.
    """
    os.makedirs(keys_dir, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_path = os.path.join(keys_dir, "cashier_ed25519_private.pem")
    public_path = os.path.join(keys_dir, "cashier_ed25519_public.pem")

    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    with open(private_path, "wb") as f:
        f.write(private_pem)
    with open(public_path, "wb") as f:
        f.write(public_pem)

    return (private_path, public_path)


def main() -> None:
    private_path, public_path = generate_keypair("sentinel_slice/keys")
    print(private_path)
    print(public_path)


if __name__ == "__main__":
    main()
