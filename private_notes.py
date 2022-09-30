# Marten Quadland
# Clare Wooten

# questions:
# 1. how to decrypt using the associated data = the nonce used to encrypt ?
# 2. how to pad messages

from multiprocessing.sharedctypes import Value
import os
import pickle
from unittest.loader import VALID_MODULE_NAME
from attr import assoc
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import padding


class PrivNotes:
    MAX_NOTE_LEN = 2048

    def __init__(self, password, data=None, checksum=None):
        # we always need a password input
        if password is None:
            raise ValueError("no password entered")

        # case 1: If data is not provided, then this method should initialize an empty note database with the
        # provided password as the password
        if data is None:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=os.urandom(16),
                iterations=2000000,
                backend=backends.default_backend(),
            )

            self.salt_hex = kdf._salt.hex()
            self.key = kdf.derive(bytes(password, "ascii"))
            h = hmac.HMAC(self.key, hashes.SHA256())
            h.update(b"hmackey")
            self.hmac_key = h.finalize()
            h = hmac.HMAC(self.key, hashes.SHA256())
            h.update(b"aeskey")
            self.aes_key = h.finalize()

            self.kvs = {}
            self.nonce = 0

            h = hmac.HMAC(self.key, hashes.SHA256())
            h.update(bytes(password, "ascii"))
            self.hmac_password = h.finalize()
            self.kvs["hmac_password"] = self.hmac_password

        # case 2: If data is not none, check inputs and load notes from data
        else:
            # load the kvs from data
            self.kvs = pickle.loads(bytes.fromhex(data))
            # retrieve the old salt
            old_salt = self.kvs["salt"]
            old_salt = bytes.fromhex(old_salt)

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=old_salt,
                iterations=2000000,
                backend=backends.default_backend(),
            )

            self.nonce = 0
            self.key = kdf.derive(bytes(password, "ascii"))

            # check to make sure password is correct
            h = hmac.HMAC(self.key, hashes.SHA256())
            h.update(bytes(password, "ascii"))
            self.hmac_password = h.finalize()
            if self.kvs["hmac_password"] != self.hmac_password:
                raise ValueError("password incorrect")

            h = hmac.HMAC(self.key, hashes.SHA256())
            h.update(b"hmackey")
            self.hmac_key = h.finalize()
            h = hmac.HMAC(self.key, hashes.SHA256())
            h.update(b"aeskey")
            self.aes_key = h.finalize()

            # if we have a data value, we need a checksum value
            if checksum is not None:
                # check to make sure data is not malformed
                # check checksum
                h_hash = hashes.Hash(hashes.SHA256())
                h_hash.update(bytes(data, "ascii"))
                checksum_check = h_hash.finalize()
                checksum_check = checksum_check.hex()
                if checksum_check != checksum:
                    raise ValueError("checksum incorrect")
            else:
                raise ValueError("checksum is None")

    def dump(self):
        self.kvs["salt"] = self.salt_hex
        # serialize data
        ser_data = pickle.dumps(self.kvs).hex()
        # create checksum
        h = hashes.Hash(hashes.SHA256())
        h.update(bytes(ser_data, "ascii"))
        checksum = h.finalize()
        checksum = checksum.hex()

        return ser_data, checksum

    def get(self, title):
        # need to derive a new key from "self.key"
        h = hmac.HMAC(self.hmac_key, hashes.SHA256())
        h.update(bytes(title, "ascii"))
        hmac_title = h.finalize()

        aesgcm = AESGCM(self.aes_key)

        if hmac_title in self.kvs:
            nonce = self.kvs[hmac_title][0]
            padded_note = aesgcm.decrypt(
                (nonce).to_bytes(16, "little"), self.kvs[hmac_title][1], hmac_title
            )
            note = self.unpad(padded_note)
            return note.decode("ascii")
        return None

    def set(self, title, note):

        if len(note) > self.MAX_NOTE_LEN:
            raise ValueError("Maximum note length exceeded")

        h = hmac.HMAC(self.hmac_key, hashes.SHA256())
        h.update(bytes(title, "ascii"))
        hmac_title = h.finalize()

        aesgcm = AESGCM(self.aes_key)
        byte_note = bytes(note, "ascii")
        # TODO: pad all notes to be 2048 bytes
        padded_note = self.pad(byte_note)
        aes_note = aesgcm.encrypt(
            (self.nonce).to_bytes(16, "little"), padded_note, hmac_title
        )
        self.kvs[hmac_title] = (self.nonce, aes_note)
        self.nonce += 1

    def remove(self, title):
        # need to derive a new key from "self.key"
        h = hmac.HMAC(self.hmac_key, hashes.SHA256())
        h.update(bytes(title, "ascii"))
        hmac_title = h.finalize()

        if hmac_title in self.kvs:
            del self.kvs[hmac_title]
            return True

        return False

    def pad(self, unpadded_note):
        # value is the unpadded note in bytes
        difference = self.MAX_NOTE_LEN - len(unpadded_note)
        padding = bytearray(b"\x11")
        padding = padding + (b"\00" * difference)
        padded_note = unpadded_note + padding
        padded_note = bytes(padded_note)
        return padded_note

    def unpad(self, padded_note):
        padded_note_array = bytearray(padded_note)
        index = 2048
        x = padded_note_array[2048]
        while x == 0:
            index = index - 1
            x = padded_note_array[index]
        unpadded_note = bytes(padded_note_array[:index])
        return unpadded_note
