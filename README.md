# LibECIES
A minimalistic curve25519 ECIES library for P2P apps
## Attention
A recent research showed that OpenSSL's EC implementation is prone to fault attacks: https://eprint.iacr.org/2019/400
Untill either OpenSSL Foundation or the author addresses this issue formally it **is not advised to use this library in production**

## Installation
### Dependencies:
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
