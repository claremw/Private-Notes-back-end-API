# Marten Quadland
# Clare Wooten

""" 
You will implement the API for a back-end implementation of a note taking application. The note taking
application will internally maintain a key-value store that maps note titles (keys) to notes (values). For our
purposes, note titles will always be unique. The API will support serialization and deserialization methods
for loading and writing the contents of the notes to disk (or cloud storage), as well as methods for adding,
fetching, and removing notes. We impose the following security requirements on both the serialized as
well as the in-memory representation of the key-value store:

String encoding: Throughout this project, you may assume that all notes and titles are ASCII strings.

Title encoding: We want to hide the note titles while still enabling efficient look-ups. To support
this, instead of using the title x itself as the key in the key-value store, you will use HMAC(k,x),
where k is an HMAC key.

Note storage: The notes in the key-value store should be encrypted using an authenticated encryption scheme. 
Since there can be a large number of notes stored, each note should be encrypted
and stored separately. You should not encrypt the entire contents of the key-value store as a single
ciphertext (otherwise, you would have to decrypt all the notes for each lookup).

Hiding note length: The application should not leak any information about the length of the notes
or titles. To make this feasible, you may assume that the maximum length of any note is 2KB.

Key derivation: The note-taking application itself is protected by a password. When the user
initializes the application or loads the notes from disk, they must provide the password. The
password should be used to derive a single 256-bit (32 byte) source key. If you need additional
cryptographic keys, you should find a way to derive them from the source key. In this assignment,
you will use the password-based key-derivation function (PBKDF2) with 2,000,000 iterations of
SHA-256 to derive your source key: 
  kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = <YOUR SALT HERE>,
  iterations = 2000000, backend = default_backend())
  key = kdf.derive(bytes(password, ’ascii’))
The application is not allowed to include the password in its source code (or any value that leaks
information about the password in its serialized representation). For instance, including a hash of
the password is not secure. Because PBKDF2 is designed to be a “slow” hash function, you can call
it at most once in your implementation.

Password salting: When using PBKDF2 to derive keys, you should always use a randomly-generated
salt. In this assignment, you should use a randomly-generated 128-bit salt (e.g., can be obtained by
calling os.urandom(16)). The salt does not have to be secret, and can be stored in the clear in your
serialized representation.

No external sources of randomness: Since good sources of randomness are expensive and not always available, 
you cannot use any external sources of randomness other than for generating the salt for PBKDF2. 
This means that you cannot call methods like AESGCM.generate_key or secrets.choice anywhere in your 
implementation. All cryptographic keys and sources of randomness that you rely on should be (securely) 
derived from the source key output by PBKDF2.

No secrets in code: You should not rely on any hard-coded secrets in your source code. You should
assume that the adversary has complete knowledge of your source code.

"""

from multiprocessing.sharedctypes import Value
import os
import pickle
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import re


class PrivNotes:
    MAX_NOTE_LEN = 2048

    def __init__(self, password, data=None, checksum=None):
        """
        Constructor.
        Args:
          password (str) : password for accessing the notes
          data (str) [Optional] : a hex-encoded serialized representation to load (defaults to None, which
                                  initializes an empty notes database)
          checksum (str) [Optional] : a hex-encoded checksum used to protect the data against possible rollback
                                      attacks (defaults to None, in which case, no rollback protection is guaranteed)
        Raises:
          ValueError : malformed serialized format

        If data is not provided, then this method should initialize an empty note database with the
        provided password as the password. Otherwise, it should load the notes from data. In addition, if the checksum
        is provided, the application should additionally validate the contents of the notes database against
        the checksum. If the provided data is malformed, the password is incorrect, or the checksum (if provided)
        is invalid, this method must raise a ValueError. If this method is called with the wrong password, i.e.,
        not the password used to initialize the provided data, your code must return a ValueError, and no other
        queries can be performed unless the client calls init successfully. It is incorrect for your application
        to pretend like nothing is wrong when the wrong password is provided and only fail to answer queries later.
        """

        # we always need a password input
        if password is None:
            raise ValueError("no password entered")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            iterations=2000000,
            backend=backends.default_backend(),
        )
        self.key = kdf.derive(bytes(password, "ascii"))

        # case 1: If data is not provided, then this method should initialize an empty note database with the
        # provided password as the password
        if data is None:
            self.kvs = {}
            self.nonce = 0
        # case 2: If data is not none, check inputs and load notes from data
        else:
            # if we have a data value, we need a checksum value (go ahead and make sure it's not malformed)
            # TODO: change checksum check to make sure it's just the sha256 of the data
            # TODO: change the data check to just make sure it's still a dictionary when it's unserialized
            if re.fullmatch(r"^[0-9a-fA-F]+$", checksum) is not None:
                # check to make sure data is not malformed
                if re.fullmatch(r"^[0-9a-fA-F]+$", data) is not None:
                    print("hi")
                # TODO: check password by making sure it can unencrypt the data
                else:
                    raise ValueError("data is malformed")
            else:
                raise ValueError("checksum is malformed")

    def dump(self):
        """
        Computes a serialized representation of the notes database
        together with a checksum.

        This method should create a hex-encoded serialization of the contents of the notes database, such that it
        may be loaded back into memory via a subsequent call to Notes.__init__(...). It should additionally
        output a SHA-256 hash of the serialized contents (for rollback protection).

        Returns:
          data (str) : a hex-encoded serialized representation of the contents of the notes database (that can be passed to the constructor)
          checksum (str) : a hex-encoded checksum for the data used to protect against rollback attacks (up to 32 characters in length)
        """
        # serialize data
        ser_data = pickle.dumps(self.kvs).hex()
        # create checksum
        # TODO: change below bc we can't use hashlib
        checksum = hashlib.sha256(bytes(ser_data, "ascii")).hexdigest()

        return ser_data, checksum

    def get(self, title):
        """
        Fetches the note associated with a title.

           If the requested title is in the notes database, then this method should return the note associated with the
           title. If the requested title is not in the database, then thismethod should return None.

        Args:
          title (str) : the title to fetch

        Returns:
          note (str) : the note associated with the requested title if
                           it exists and otherwise None
        """

        # need to derive a new key from "self.key"
        """
        h = hmac.HMAC(self.key, hashes.SHA256())
        h.update(title)
        hmac_title = h.finalize()
        """
        if title in self.kvs:
            return self.kvs[title]
        return None

    def set(self, title, note):
        """
        Associates a note with a title and adds it to the database
        (or updates the associated note if the title is already
        present in the database).

        This method should insert the title together with its associated note into the database. If the title is already
        in the database, this method will update its value. Otherwise, it will create a new entry. If note is more
        than 2KB, this method should abort with a ValueError.

        Args:
          title (str) : the title to set
          note (str) : the note associated with the title

        Returns:
          None

        Raises:
          ValueError : if note length exceeds the maximum
        """
        if len(note) > self.MAX_NOTE_LEN:
            raise ValueError("Maximum note length exceeded")

        h = hmac.HMAC(self.key, hashes.SHA256())
        h.update(title)
        hmac_title = h.finalilze()

        aesgcm = AESGCM(self.key)
        aes_note = aesgcm.encrypt(self.nonce, note, self.nonce)

        self.kvs[hmac_title] = aes_note

    def remove(self, title):
        """
        Removes the note for the requested title from the database.

        Removes the target title fromthe database. If the requested title is found, then this method should remove
        it and return True. If the title is not found, return False.

        Args:
          title (str) : the title to remove

        Returns:
          success (bool) : True if the title was removed and False if the title was
                           not found
        """
        # need to derive a new key from "self.key"
        # h = hmac.HMAC(self.key, hashes.SHA256())
        # h.update(title)
        # hmac_title = h.finalize()

        if title in self.kvs:
            del self.kvs[title]
            return True

        return False
