# aes_unknown_keys
Tests keys from stdin on the first block of an encrypted file to see if they match a known plaintext, using AES 128 CBC
with an optional initialization vector (IV) and no padding.

Supports parallelization, though that has shown to provide only small improvements.

## Example Usage
```
cat <some key list> | aes_unknown_keys <encrypted file> <known beginning plaintext> [<iv = 0x00 * 16> <num_threads = 4> <output_bad_attempts = false>]
```

## Note
It's entirely unrealistic to attempt to brute-force AES keys, even at only 128-bits. This tool is designed for
situations where key generation is performed using a known algorithm (with which you use a password list of some kind)
or if the key could be in a list.
