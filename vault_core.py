#!/usr/bin/env python3

# Encryption core for senitel, kept separate from the GUI so it can be
# imported and tested without a display.

import hashlib
import os
import shutil
import zipfile

import pyAesCrypt

BUFFER_SIZE = 1024 * 1024 * 128
ENCRYPTED_NAME = ".senitel.encrypt"
ARCHIVE_NAME = "vault.zip"
VAULT_DIR = "vault"

# Stretches a password and seed into a key. The seed is folded in so the same
# password produces a different key for a different seed, and the loop count
# is high on purpose: it is the only thing standing between a stolen archive
# and a brute-force attempt against it.
def derive_key(password, seed, rounds=10128):
    key = f"*%|E{seed}(0{password}^2f#bw$"
    for _ in range(rounds):
        key = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return key

# Overwrites a file with junk before removing it, so the bytes on disk are
# not simply recoverable from the free list after deletion. Directories are
# removed outright: there is nothing to overwrite in a directory entry itself.
def secure_delete(path, passes=3, chunk_size=1024 * 1024):
    if not os.path.exists(path):
        return
    if os.path.isdir(path):
        shutil.rmtree(path)
        return
    length = os.path.getsize(path)
    with open(path, "r+b") as handle:
        for _ in range(passes):
            handle.seek(0)
            remaining = length
            while remaining > 0:
                handle.write(os.urandom(min(chunk_size, remaining)))
                remaining -= min(chunk_size, remaining)
            handle.flush()
            os.fsync(handle.fileno())
    os.remove(path)

# True when the vault is sitting on disk unencrypted, ready to be locked.
def is_unlocked(directory="."):
    return os.path.isdir(os.path.join(directory, VAULT_DIR))

# True when the vault is sealed in its encrypted archive.
def is_locked(directory="."):
    return os.path.isfile(os.path.join(directory, ENCRYPTED_NAME))

# Zips the vault directory, encrypts the archive, and securely deletes the
# plaintext copies. Raises on a real I/O problem; a wrong password cannot
# occur here since encrypting never checks one.
def lock(password, seed, directory="."):
    vault_path = os.path.join(directory, VAULT_DIR)
    archive_path = os.path.join(directory, ARCHIVE_NAME)
    encrypted_path = os.path.join(directory, ENCRYPTED_NAME)

    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_STORED) as archive:
        for root, _dirs, files in os.walk(vault_path):
            for name in files:
                full_path = os.path.join(root, name)
                archive.write(full_path, os.path.relpath(full_path, directory))

    key = derive_key(password, seed)
    pyAesCrypt.encryptFile(archive_path, encrypted_path, key, BUFFER_SIZE)
    secure_delete(archive_path)
    secure_delete(vault_path)

# Decrypts the archive and unpacks it back into the vault directory. Raises
# ValueError on a wrong password: pyAesCrypt itself reports a bad password as
# an integrity check failure, and that is translated into one clear error
# here so callers do not need to know pyAesCrypt's exception types.
def unlock(password, seed, directory="."):
    encrypted_path = os.path.join(directory, ENCRYPTED_NAME)
    archive_path = os.path.join(directory, ARCHIVE_NAME)
    key = derive_key(password, seed)

    try:
        pyAesCrypt.decryptFile(encrypted_path, archive_path, key, BUFFER_SIZE)
    except ValueError:
        raise ValueError("incorrect password or seed")

    with zipfile.ZipFile(archive_path, "r") as archive:
        archive.extractall(directory)
    secure_delete(archive_path)
    secure_delete(encrypted_path)

# Locks an unlocked vault, or unlocks a locked one. Whichever state the
# vault is not in is treated as an error, since there is no vault to act on.
def toggle(password, seed, directory="."):
    if is_unlocked(directory):
        lock(password, seed, directory)
        return "locked"
    if is_locked(directory):
        unlock(password, seed, directory)
        return "unlocked"
    raise FileNotFoundError("no vault directory or encrypted archive found")
