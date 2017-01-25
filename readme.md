# CSSCrypt
Clyde’s Simple Shuffler Encryption.
Encryption which requires two keys to encrypt and decrypt. First key is used to encode the message, second, shifts each encrypted character according to each single digit in the key.

You can find the javascript version [here](https://github.com/csmets/csscrypt-js).

## How to use
```python
shiftKey = '3453465'
CSSCrypt = CSSCrypt.encryption()
encMsg = CSSCrypt.encrypt('My Secret Message', shiftKey)
print (encMsg)
print(CSSCrypt.decrypt(encMsg, shiftKey))

>>>WbpjY8amgrY4OJ4ph6Rne5Y==
>>>My Secret Message
```

Please change the values in `key/encoding.txt` to maximise security. Currently it's using Base64, but it would be smarter to make something up and not use a public key. 

**Note**

Top value is bit size.

Bottom value is padding character

Make sure each value is unique.

**Have fun!**
