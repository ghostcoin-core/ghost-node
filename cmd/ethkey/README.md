ethkey
======

ethkey is a simple command-line tool for working with Ghost account keyfiles.
An account key is an ML-DSA-44 key pair (scheme 0x0001), held in the keyfile
as the 32-byte seed it is derived from, encrypted with a password; the keyfile
carries a scheme field set to 1. Keyfiles that hold secp256k1 keys are refused.


# Usage

### `ethkey generate`

Generate a new keyfile.
If you want to use an existing key seed in the keyfile, it can be
specified by setting `--seed` with the location of the file containing the
32-byte seed in hex.


### `ethkey inspect <keyfile>`

Print various information about the keyfile: the address, the scheme and the
public key.
The key seed can be printed by using the `--private` flag;
make sure to use this feature with great caution!


### `ethkey changepassword <keyfile>`

Change the password of a keyfile.
use the `--newpasswordfile` to point to the new password file.


There are no message signing commands: they signed secp256k1 message
signatures, and no quantum-safe message signature is specified.


## Passwords

For every command that uses a keyfile, you will be prompted to provide the 
password for decrypting the keyfile.  To avoid this message, it is possible
to pass the password by using the `--passwordfile` flag pointing to a file that
contains the password.

## JSON

In case you need to output the result in a JSON format, you shall by using the `--json` flag.
