from crypto import *

key='shdM#9odQa/**5wng0dX+'

plaintext=b'abcd'

#---------------------------------------------

ciphertext=encrypt(plaintext, key)

with open('ciphertext.enc', mode='wb') as f: f.write(ciphertext)

#---------------------------------------------

with open('ciphertext.enc', mode='rb') as f: ciphertext=f.read()

plaintext=decrypt(ciphertext, key)

if plaintext==False: print('Decryption error!')
else: print('Plaintext:', plaintext)

#---------------------------------------------

input('Press any key to quit...')
