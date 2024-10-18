# Cyberfrog (firmware)

## How to run

Make sure you have [esp-idf](https://github.com/espressif/esp-idf) installed.

1. `idf.py set_target esp32c3`
2. `idf.py build flash monitor`

## Design

## Hardware

1.  Each Cyberfrog has a keypair

- Currently using ECDSA (for `ecrecover`)
- Can use RSA if we need flash encryption + hardware acceleration

2. The keypair signs an incrementing nonce (uint32) every time someone reads the NFC tag
3. We write the nonce and signature to the NFC tag:

- `zupass.org/embedded-zapps/frogcrypto?embedded-params={nonce=<nonce>&sig=<signature>&pubkey=<pubkey>}`

### Hardware setup

1. Generate keypair for each Cyberfrog
2. Save the public key to the FrogCrypto server DB

- We need to derive a stable UUID from the public key, can convert to bigint and then to UUID

## Claiming flow

1. User scans NFC tag. This gives them the most recently signed nonce
2. A new nonce is generated and stored in the tag. If I scan again, I get rate-limited. However, a new nonce is generated anyway.
3. This means we need to make sure the nullifier is created even if the rate limit is hit
4. Zupass link opens embedded FrogCrypto app: `frogcrypto.xyz/cyberfrog?nonce=<nonce>&sig=<signature>&pubkey=<pubkey>`
5. FrogCrypto server

- Verifies the signature
- Checks if the nonce has been used before
- We issue a new frog and reset the rate limit (use the same feed logic as FrogCrypto)

## Important Notes

- The CyberFrog always signs an incrementing nonce on NFC tag read, regardless of server-side claim status or rate limit

We need the following tables:

- Nullifiers table:

  - `id`: primary key
  - `nullifier`: sha256(public_key, nonce)
  - `created_at`: timestamp

Unique constraint on `nullifier`

# TODO

- [ ] Prevent people from writing to the NFC tag (this is important)
