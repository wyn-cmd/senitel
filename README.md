# Senitel
A vault encrypted with AES-256 in python3 and tkinter. The password and a separate seed are stretched through 10,128 rounds of sha256 before either one ever reaches the encryption library, and the plaintext copies are overwritten before being deleted rather than just unlinked.

# Installation
```
chmod +x install.sh
./install.sh
```

# Running it
```
./senitel
```
Type a password and a seed, then press enter. If `vault/` exists it gets locked into `.senitel.encrypt`; if `.senitel.encrypt` exists instead it gets unlocked back into `vault/`. Getting either value wrong is reported rather than silently producing a corrupt vault.

# Testing
The vault logic lives in `vault_core.py`, separate from the GUI, so it can be tested without a display:
```
pip install -r requirements.txt
python3 -m unittest test_vault_core -v
```
