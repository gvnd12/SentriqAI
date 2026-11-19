import hashlib
import hmac
import secrets

WEBHOOK_SECRET_PREFIX = "whsec_"


def generate_webhook_secret() -> tuple[str, str]:
    random_secret = secrets.token_urlsafe(32)
    plaintext_secret = f"{WEBHOOK_SECRET_PREFIX}{random_secret}"

    secret_hash = hash_webhook_secret(plaintext_secret)

    return plaintext_secret, secret_hash


def hash_webhook_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def verify_webhook_secret(plaintext_secret: str, stored_hash: str) -> bool:
    candidate_hash = hash_webhook_secret(plaintext_secret)
    return hmac.compare_digest(candidate_hash, stored_hash)
