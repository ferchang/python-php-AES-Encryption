from Crypto.Cipher import AES
from Crypto import Random
from hmac import compare_digest
from binascii import hexlify

#================HKDF================
import hashlib
import hmac
from math import ceil

hash_len = 32
def hmac_sha256(key, data):
	return hmac.new(key, data, hashlib.sha256).digest()

def hkdf(length, ikm, salt=b'', info=b''):
	prk = hmac_sha256(salt, ikm)
	t = b""
	okm = b""
	for i in range(ceil(length / hash_len)):
		t = hmac_sha256(prk, t + info + bytes([1+i]))
		okm += t
	return okm[:length]
#================HKDF================

BLOCK_SIZE=16
pad=lambda s: s+((BLOCK_SIZE-len(s)%BLOCK_SIZE)*chr(BLOCK_SIZE-len(s)%BLOCK_SIZE)).encode()
unpad = lambda s : s[:-ord(s[len(s)-1:])]

def str22keys(str):
	keys=hkdf(BLOCK_SIZE*2, str.encode())
	return keys[:BLOCK_SIZE], keys[BLOCK_SIZE:]

def encrypt(data, key):

	key, key2=str22keys(key)
	
	data=pad(data)
	iv=Random.new().read(BLOCK_SIZE)
	aes=AES.new(key, AES.MODE_CBC, iv)
	
	ct=iv+aes.encrypt(data)
	
	return hmac_sha256(key2, ct)+ct

def decrypt(data, key):
		
	key, key2=str22keys(key)
		
	hmac1=data[:32]
	ct=data[32:]
	
	if not compare_digest(hmac_sha256(key2, ct), hmac1):
		print('hmac verification failed!')
		return None
	
	iv=ct[:BLOCK_SIZE]
	aes=AES.new(key, AES.MODE_CBC, iv)
	return unpad(aes.decrypt(ct[BLOCK_SIZE:]))
