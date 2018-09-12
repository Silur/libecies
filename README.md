# LibECIES

A minimalistic curve25519 ECIES library for P2P apps

Requires:
- gcc > 8
- openssl >= 1.1.0

`make` should create a static lib you can link to

use `make test` to create a test executable

Usage is in `ecies.h`



## Why ECIES instead of ECDH-AES?

They are fundamentally not so different, basically ECIES is a form of ECDH-AES where the sender
creates a new keypair every time and sends her public key with the ciphertext + a HMAC.

**Pro:** 

- Forward secrecy
- No mixing of signing and encryption keys

**Contra**: 

- Minor communication overhead

## TODO

- Better error handling
- Proper memory cleanup on failures
