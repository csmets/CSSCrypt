# Testing CSSCrypt
import CSSCrypt

shiftKey = '3453465'
CSSCrypt = CSSCrypt.encryption()
encMsg = CSSCrypt.encrypt('My Secret Message', shiftKey)
print (encMsg)
print(CSSCrypt.decrypt(encMsg, shiftKey))
