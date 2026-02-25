from typing import BinaryIO

from dissect.extfs.exceptions import DecryptionError


class EntryDecryptor:
    """ExtFS INodes need to be able to call an external class to handle its decryption. This class defines the
    interface and is assigned by default when no decryption handler is given. It will raise a DecryptionError when
    called."""

    def decrypt_filename(self, encrypted_filename: bytes) -> bytes:
        raise DecryptionError("No decryptor available")

    def open_decrypt(self) -> BinaryIO:
        raise DecryptionError("No decryptor available")
