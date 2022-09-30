# Marten Quadland
# Clare Wooten

# questions:
# 1. how to decrypt using the associated data = the nonce used to encrypt ?
# 2. how to pad messages

from multiprocessing.sharedctypes import Value
import os
import pickle
from attr import assoc
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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
            h = hmac.HMAC(kdf._salt, hashes.SHA256())
            h.update(self.key)
            keyexpanded = h.finalize()
            self.hmac_key = keyexpanded[:16]
            self.aes_key = keyexpanded[16:]

            self.kvs = {}
            self.nonce = 0
            self.nonce_bytes = (0).to_bytes(16, "little")

        # case 2: If data is not none, check inputs and load notes from data
        else:
            # derive new key with the old salt value
            # old salt value is the first 32 hex digits
            old_salt = bytes.fromhex(data[:32])
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=old_salt,
                iterations=2000000,
                backend=backends.default_backend(),
            )
            self.nonce = 0
            self.nonce_bytes = (0).to_bytes(16, "little")
            self.key = kdf.derive(bytes(password, "ascii"))

            h = hmac.HMAC(old_salt, hashes.SHA256())
            h.update(self.key)
            keyexpanded = h.finalize()
            self.hmac_key = keyexpanded[:16]
            self.aes_key = keyexpanded[16:]

            # if we have a data value, we need a checksum value (go ahead and make sure it's not malformed)
            # TODO: change checksum check to make sure it's just the sha256 of the data
            # TODO: change the data check to just make sure it's still a dictionary when it's unserialized
            if checksum is not None:
                # check to make sure data is not malformed
                # check checksum
                h_hash = hashes.Hash(hashes.SHA256())
                h_hash.update(bytes(data[32:], "ascii"))
                checksum_check = h_hash.finalize()
                checksum_check = checksum_check.hex()
                if checksum_check == checksum:
                    # check password by making sure it can unencrypt the data
                    self.kvs = pickle.loads(bytes.fromhex(data[32:]))
                    aesgcm = AESGCM(self.aes_key)
                    # calling .values on self.kvs simultaneously checks to ensure it's a dictionary
                    aesgcm.decrypt(
                        self.nonce_bytes, list(self.kvs.values())[0], self.nonce_bytes
                    )
                else:
                    raise ValueError("checksum incorrect")
            else:
                raise ValueError("checksum is None")

    def dump(self):
        # serialize data
        ser_data = pickle.dumps(self.kvs).hex()
        # create checksum
        h = hashes.Hash(hashes.SHA256())
        h.update(bytes(ser_data, "ascii"))
        checksum = h.finalize()
        checksum = checksum.hex()

        return self.salt_hex + ser_data, checksum

    def get(self, title):
        # need to derive a new key from "self.key"
        h = hmac.HMAC(self.hmac_key, hashes.SHA256())
        h.update(bytes(title, "ascii"))
        hmac_title = h.finalize()

        aesgcm = AESGCM(self.aes_key)

        if hmac_title in self.kvs:
            note_bytesarray = bytearray(self.kvs[hmac_title])
            ad = bytes(note_bytesarray[(len(note_bytesarray) - 16) :])
            print(ad)
            print(len(ad))
            note = aesgcm.decrypt(ad, self.kvs[hmac_title], ad)
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
        # TODO: took off "self.nonce" from 3rd parameter
        aes_note = aesgcm.encrypt(self.nonce_bytes, byte_note, None)
        self.nonce += 1
        self.nonce_bytes = (self.nonce).to_bytes(16, "little")

        self.kvs[hmac_title] = aes_note
        print(self.nonce)
        print(aes_note)

    def remove(self, title):
        # need to derive a new key from "self.key"
        h = hmac.HMAC(self.hmac_key, hashes.SHA256())
        h.update(bytes(title, "ascii"))
        hmac_title = h.finalize()

        if hmac_title in self.kvs:
            del self.kvs[hmac_title]
            return True

        return False
