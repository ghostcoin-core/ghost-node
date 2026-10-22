ethkey
======

ethkey is a simple command-line tool for working with ML-DSA-44 account
keyfiles. A keyfile holds the password-encrypted 32-byte seed of the key and
has `"scheme":1`; secp256k1 keyfiles are not supported.


# Usage

### `ethkey generate`

Generate a new keyfile and print its address, scheme and public key.
If you want to use an existing key seed in the keyfile, it can be
specified by setting `--seed` with the location of a file containing the
32-byte seed in hex.


### `ethkey inspect <keyfile>`

Print the address, scheme and public key of the keyfile.
The secret seed can be printed by using the `--private` flag;
make sure to use this feature with great caution!


### `ethkey changepassword <keyfile>`

Change the password of a keyfile.
use the `--newpasswordfile` to point to the new password file.


## Passwords

For every command that uses a keyfile, you will be prompted to provide the 
password for decrypting the keyfile.  To avoid this message, it is possible
to pass the password by using the `--passwordfile` flag pointing to a file that
contains the password.

## JSON

In case you need to output the result in a JSON format, you shall by using the `--json` flag.
