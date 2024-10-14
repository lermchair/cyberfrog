# Cyberfrog (firmware)

## How to run

Make sure you have [esp-idf](https://github.com/espressif/esp-idf) installed.

1. `idf.py set_target esp32c3`
2. `idf.py build flash monitor`

## Design

## Hardware
1.  Each Cyberfrog has a keypair
  - Currently using RSA
  - TODO: evaluate ECDSA (so we can use `ecrecover`)
2. The keypair signs an incrementing nonce (uint32) every time someone reads the NFC tag
3. We write the nonce and signature to the NFC tag:
  - `zupass.org/embedded-zapps/frogcrypto?embedded-params={nonce=<nonce>&sig=<signature>&pubkey=<pubkey>}`

### Hardware setup
1. Generate keypair for each Cyberfrog
2. Save the public key to the FrogCrypto server DB
  -  We need to derive a stable UUID from the public key, can convert to bigint and then to UUID

## Claiming flow
1. User scans NFC tag
2. Zupass link opens embedded FrogCrypto app: `frogcrypto.xyz/cyberfrog?nonce=<nonce>&sig=<signature>&pubkey=<pubkey>`
3. FrogCrypto server
  - Verifies the signature
  - Checks if the nonce has been used before
  - We issue a new frog and reset the rate limit (use the same feed logic as FrogCrypto)

## Important Notes
- The CyberFrog always signs an incrementing nonce on NFC tag read, regardless of server-side claim status or rate limit

We need the following tables:
- Nullifiers table:
  - `id`: primary key
  - `public_key`: the public key of the Frog
  - `nonce`: last used nonce
Unique constraint on `public_key` and `nonce`

- Cyberfrogs table:
  - `id`: the public key of the Frog, can be the primary key

## Questions
- What is the easiest/fastest way to save public keys during setup? Maybe put everything in a JSON file and then just do a bulk insert


# TODO
- [ ] Prevent people from writing to the NFC tag (this is important)
