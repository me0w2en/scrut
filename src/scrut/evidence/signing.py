"""Bundle signing and verification for evidence integrity.

Supports RSA and Ed25519 signatures for forensic evidence bundles.
Provides cryptographic proof of bundle authenticity and integrity.
"""

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel


SignatureAlgorithm = Literal["rsa-sha256", "ed25519"]


class SignatureInfo(BaseModel):
    """Metadata about a bundle signature."""

    algorithm: SignatureAlgorithm
    key_id: str
    signed_at: datetime
    signature: str
    manifest_hash: str
    signer_name: str | None = None
    signer_email: str | None = None


class SignatureResult(BaseModel):
    """Result of a signing or verification operation."""

    success: bool
    message: str
    signature_info: SignatureInfo | None = None
    errors: list[str] = []


@dataclass
class SigningKey:
    """A signing key (private) for creating signatures."""

    algorithm: SignatureAlgorithm
    key_id: str
    private_key_pem: bytes
    signer_name: str | None = None
    signer_email: str | None = None


@dataclass
class VerificationKey:
    """A verification key (public) for verifying signatures."""

    algorithm: SignatureAlgorithm
    key_id: str
    public_key_pem: bytes


class BundleSigner:
    """Signs evidence bundles for integrity verification."""

    def __init__(self, signing_key: SigningKey) -> None:
        """Initialize with a signing key.

        Args:
            signing_key: Private key for signing
        """
        self._key = signing_key

    def sign_manifest(self, manifest_path: Path) -> SignatureResult:
        """Sign a bundle manifest file.

        Args:
            manifest_path: Path to manifest.json

        Returns:
            SignatureResult with signature info
        """
        try:
            manifest_data = manifest_path.read_bytes()
            manifest_hash = hashlib.sha256(manifest_data).hexdigest()

            signature_bytes = self._create_signature(manifest_data)
            signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

            signature_info = SignatureInfo(
                algorithm=self._key.algorithm,
                key_id=self._key.key_id,
                signed_at=datetime.now(timezone.utc),
                signature=signature_b64,
                manifest_hash=manifest_hash,
                signer_name=self._key.signer_name,
                signer_email=self._key.signer_email,
            )

            signature_path = manifest_path.parent / "signature.json"
            signature_path.write_text(
                json.dumps(signature_info.model_dump(mode="json"), indent=2)
            )

            return SignatureResult(
                success=True,
                message=f"Bundle signed successfully with {self._key.algorithm}",
                signature_info=signature_info,
            )

        except Exception as e:
            return SignatureResult(
                success=False,
                message="Signing failed",
                errors=[str(e)],
            )

    def _create_signature(self, data: bytes) -> bytes:
        """Create signature using the configured algorithm."""
        if self._key.algorithm == "rsa-sha256":
            return self._sign_rsa(data)
        elif self._key.algorithm == "ed25519":
            return self._sign_ed25519(data)
        else:
            raise ValueError(f"Unsupported algorithm: {self._key.algorithm}")

    def _sign_rsa(self, data: bytes) -> bytes:
        """Sign data using RSA-SHA256."""
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding, rsa

            private_key = serialization.load_pem_private_key(
                self._key.private_key_pem, password=None
            )

            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise ValueError("Key is not an RSA private key")

            signature = private_key.sign(
                data,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return signature

        except ImportError:
            raise ImportError(
                "cryptography package required for RSA signing. "
                "Install with: pip install cryptography"
            )

    def _sign_ed25519(self, data: bytes) -> bytes:
        """Sign data using Ed25519."""
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ed25519

            private_key = serialization.load_pem_private_key(
                self._key.private_key_pem, password=None
            )

            if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                raise ValueError("Key is not an Ed25519 private key")

            signature = private_key.sign(data)
            return signature

        except ImportError:
            raise ImportError(
                "cryptography package required for Ed25519 signing. "
                "Install with: pip install cryptography"
            )


class BundleVerifier:
    """Verifies evidence bundle signatures."""

    def __init__(self, verification_keys: list[VerificationKey] | None = None) -> None:
        """Initialize with optional verification keys.

        Args:
            verification_keys: List of public keys for verification
        """
        self._keys: dict[str, VerificationKey] = {}
        if verification_keys:
            for key in verification_keys:
                self._keys[key.key_id] = key

    def add_key(self, key: VerificationKey) -> None:
        """Add a verification key."""
        self._keys[key.key_id] = key

    def verify_bundle(self, bundle_path: Path) -> SignatureResult:
        """Verify a signed bundle.

        Args:
            bundle_path: Path to bundle directory

        Returns:
            SignatureResult with verification status
        """
        errors = []

        signature_path = bundle_path / "signature.json"
        if not signature_path.exists():
            return SignatureResult(
                success=False,
                message="Bundle is not signed",
                errors=["signature.json not found"],
            )

        try:
            signature_data = json.loads(signature_path.read_text())
            signature_info = SignatureInfo(**signature_data)
        except Exception as e:
            return SignatureResult(
                success=False,
                message="Invalid signature file",
                errors=[str(e)],
            )

        manifest_path = bundle_path / "manifest.json"
        if not manifest_path.exists():
            return SignatureResult(
                success=False,
                message="Manifest not found",
                errors=["manifest.json not found"],
            )

        manifest_data = manifest_path.read_bytes()
        manifest_hash = hashlib.sha256(manifest_data).hexdigest()

        if manifest_hash != signature_info.manifest_hash:
            errors.append(
                f"Manifest hash mismatch: expected {signature_info.manifest_hash}, "
                f"got {manifest_hash}"
            )

        key = self._keys.get(signature_info.key_id)
        if not key:
            return SignatureResult(
                success=False,
                message="Verification key not found",
                signature_info=signature_info,
                errors=[f"No key found for key_id: {signature_info.key_id}"],
            )

        try:
            signature_bytes = base64.b64decode(signature_info.signature)
            self._verify_signature(
                key, manifest_data, signature_bytes, signature_info.algorithm
            )
        except Exception as e:
            errors.append(f"Signature verification failed: {e}")

        if errors:
            return SignatureResult(
                success=False,
                message="Verification failed",
                signature_info=signature_info,
                errors=errors,
            )

        return SignatureResult(
            success=True,
            message="Bundle signature verified successfully",
            signature_info=signature_info,
        )

    def _verify_signature(
        self,
        key: VerificationKey,
        data: bytes,
        signature: bytes,
        algorithm: SignatureAlgorithm,
    ) -> None:
        """Verify a signature using the specified algorithm."""
        if algorithm == "rsa-sha256":
            self._verify_rsa(key, data, signature)
        elif algorithm == "ed25519":
            self._verify_ed25519(key, data, signature)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

    def _verify_rsa(
        self, key: VerificationKey, data: bytes, signature: bytes
    ) -> None:
        """Verify RSA-SHA256 signature."""
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding, rsa

            public_key = serialization.load_pem_public_key(key.public_key_pem)

            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ValueError("Key is not an RSA public key")

            public_key.verify(
                signature,
                data,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )

        except ImportError:
            raise ImportError(
                "cryptography package required for RSA verification. "
                "Install with: pip install cryptography"
            )

    def _verify_ed25519(
        self, key: VerificationKey, data: bytes, signature: bytes
    ) -> None:
        """Verify Ed25519 signature."""
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ed25519

            public_key = serialization.load_pem_public_key(key.public_key_pem)

            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                raise ValueError("Key is not an Ed25519 public key")

            public_key.verify(signature, data)

        except ImportError:
            raise ImportError(
                "cryptography package required for Ed25519 verification. "
                "Install with: pip install cryptography"
            )


def generate_key_pair(
    algorithm: SignatureAlgorithm = "ed25519",
    key_id: str | None = None,
) -> tuple[SigningKey, VerificationKey]:
    """Generate a new signing/verification key pair.

    Args:
        algorithm: Signature algorithm to use
        key_id: Optional key identifier (auto-generated if not provided)

    Returns:
        Tuple of (SigningKey, VerificationKey)
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

        if algorithm == "ed25519":
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()
        elif algorithm == "rsa-sha256":
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            public_key = private_key.public_key()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        if not key_id:
            key_id = hashlib.sha256(public_pem).hexdigest()[:16]

        signing_key = SigningKey(
            algorithm=algorithm,
            key_id=key_id,
            private_key_pem=private_pem,
        )

        verification_key = VerificationKey(
            algorithm=algorithm,
            key_id=key_id,
            public_key_pem=public_pem,
        )

        return signing_key, verification_key

    except ImportError:
        raise ImportError(
            "cryptography package required for key generation. "
            "Install with: pip install cryptography"
        )


def load_signing_key(
    key_path: Path,
    algorithm: SignatureAlgorithm,
    key_id: str | None = None,
    signer_name: str | None = None,
    signer_email: str | None = None,
) -> SigningKey:
    """Load a signing key from a PEM file.

    Args:
        key_path: Path to PEM private key file
        algorithm: Signature algorithm
        key_id: Key identifier (derived from key if not provided)
        signer_name: Optional signer name
        signer_email: Optional signer email

    Returns:
        SigningKey instance
    """
    private_pem = key_path.read_bytes()

    if not key_id:
        key_id = hashlib.sha256(private_pem).hexdigest()[:16]

    return SigningKey(
        algorithm=algorithm,
        key_id=key_id,
        private_key_pem=private_pem,
        signer_name=signer_name,
        signer_email=signer_email,
    )


def load_verification_key(
    key_path: Path,
    algorithm: SignatureAlgorithm,
    key_id: str | None = None,
) -> VerificationKey:
    """Load a verification key from a PEM file.

    Args:
        key_path: Path to PEM public key file
        algorithm: Signature algorithm
        key_id: Key identifier (derived from key if not provided)

    Returns:
        VerificationKey instance
    """
    public_pem = key_path.read_bytes()

    if not key_id:
        key_id = hashlib.sha256(public_pem).hexdigest()[:16]

    return VerificationKey(
        algorithm=algorithm,
        key_id=key_id,
        public_key_pem=public_pem,
    )
