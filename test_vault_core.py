# Tests for vault_core, run against a real scratch vault directory and
# real AES encryption via pyAesCrypt, not mocked.

import os
import shutil
import tempfile
import unittest

import vault_core


class HashingTests(unittest.TestCase):
    def test_the_same_inputs_give_the_same_key(self):
        self.assertEqual(vault_core.derive_key("hunter2", "seed-a"),
                          vault_core.derive_key("hunter2", "seed-a"))

    def test_a_different_seed_gives_a_different_key(self):
        self.assertNotEqual(vault_core.derive_key("hunter2", "seed-a"),
                             vault_core.derive_key("hunter2", "seed-b"))

    def test_a_different_password_gives_a_different_key(self):
        self.assertNotEqual(vault_core.derive_key("hunter2", "seed-a"),
                             vault_core.derive_key("hunter3", "seed-a"))

    def test_the_key_is_a_sha256_hex_digest(self):
        key = vault_core.derive_key("hunter2", "seed-a")
        self.assertEqual(len(key), 64)
        int(key, 16)  # raises if it is not hex


class LockUnlockTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="senitel-test-")
        self.addCleanup(lambda: shutil.rmtree(self.work, ignore_errors=True))
        os.makedirs(os.path.join(self.work, "vault", "notes"))
        with open(os.path.join(self.work, "vault", "diary.txt"), "w") as f:
            f.write("the vault holds this text")
        with open(os.path.join(self.work, "vault", "notes", "todo.txt"), "w") as f:
            f.write("a nested file too")

    def test_locking_removes_the_plaintext_and_leaves_an_archive(self):
        vault_core.lock("hunter2", "seed-a", self.work)
        self.assertFalse(os.path.exists(os.path.join(self.work, "vault")))
        self.assertTrue(os.path.exists(os.path.join(self.work, vault_core.ENCRYPTED_NAME)))
        self.assertFalse(os.path.exists(os.path.join(self.work, vault_core.ARCHIVE_NAME)))

    def test_unlocking_restores_the_original_files(self):
        vault_core.lock("hunter2", "seed-a", self.work)
        vault_core.unlock("hunter2", "seed-a", self.work)
        with open(os.path.join(self.work, "vault", "diary.txt")) as f:
            self.assertEqual(f.read(), "the vault holds this text")
        with open(os.path.join(self.work, "vault", "notes", "todo.txt")) as f:
            self.assertEqual(f.read(), "a nested file too")
        self.assertFalse(os.path.exists(os.path.join(self.work, vault_core.ENCRYPTED_NAME)))

    def test_the_wrong_password_is_refused(self):
        vault_core.lock("hunter2", "seed-a", self.work)
        with self.assertRaises(ValueError):
            vault_core.unlock("wrong-password", "seed-a", self.work)

    def test_the_wrong_seed_is_refused(self):
        vault_core.lock("hunter2", "seed-a", self.work)
        with self.assertRaises(ValueError):
            vault_core.unlock("hunter2", "wrong-seed", self.work)

    def test_toggle_locks_an_unlocked_vault(self):
        outcome = vault_core.toggle("hunter2", "seed-a", self.work)
        self.assertEqual(outcome, "locked")
        self.assertTrue(vault_core.is_locked(self.work))

    def test_toggle_unlocks_a_locked_vault(self):
        vault_core.lock("hunter2", "seed-a", self.work)
        outcome = vault_core.toggle("hunter2", "seed-a", self.work)
        self.assertEqual(outcome, "unlocked")
        self.assertTrue(vault_core.is_unlocked(self.work))

    def test_toggle_with_neither_state_present_is_reported(self):
        shutil.rmtree(os.path.join(self.work, "vault"))
        with self.assertRaises(FileNotFoundError):
            vault_core.toggle("hunter2", "seed-a", self.work)


class SecureDeleteTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="senitel-delete-test-")
        self.addCleanup(lambda: shutil.rmtree(self.work, ignore_errors=True))

    def test_a_file_is_removed(self):
        path = os.path.join(self.work, "secret.txt")
        with open(path, "w") as f:
            f.write("sensitive")
        vault_core.secure_delete(path)
        self.assertFalse(os.path.exists(path))

    def test_a_directory_is_removed(self):
        path = os.path.join(self.work, "folder")
        os.makedirs(path)
        with open(os.path.join(path, "f.txt"), "w") as f:
            f.write("x")
        vault_core.secure_delete(path)
        self.assertFalse(os.path.exists(path))

    def test_a_missing_path_is_a_no_op(self):
        # must not raise just because there was nothing to delete
        vault_core.secure_delete(os.path.join(self.work, "does-not-exist"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
