# SERPENT
Implementation of Serpent cipher from scratch in python3

This code is to implement Encryption and Decryption of strings with SERPENT cipher 
in Python3 without using any modules.

Serpent ranked 2nd to Rijndael(AES).

_USAGE_
ENCRYPTION:
```
$ serpent1.py -m enc -k 'c0ffee' -s 'encrypt this secret stuff'
$ serpent1.py --mode enc --key 'c0ffee' --string 'encrypt this secret stuff'
```
DECRYPTION:
```
$ serpent1.py -m dec -k 'c0ffee' -s 'decrypt this hex ciphertext'
$ serpent1.py --mode dec --key 'c0ffee' --string 'decrypt this hex ciphertext'
```
There is also serpent class
Initialize object with hexadecimal key with length as a multiple of 16 and less than 256
use encryptBlock and decryptBlock for only 128-bit binary data
