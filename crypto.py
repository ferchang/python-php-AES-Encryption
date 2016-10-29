from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256, HMAC
from hmac import compare_digest

BLOCK_SIZE=16
pad=lambda s: s+((BLOCK_SIZE-len(s)%BLOCK_SIZE)*chr(BLOCK_SIZE-len(s)%BLOCK_SIZE)).encode()
unpad = lambda s : s[:-ord(s[len(s)-1:])]

def str2key(str):
	return SHA256.new(str.encode()).digest()[:BLOCK_SIZE]

def encrypt(data, key):
	
	if not len(data):
		print('no data to encrypt!')
		return None
	if not len(key):
		print('no encryption key!')
		return None
	
	key=str2key(key)
	
	data=pad(data)
	iv=Random.new().read(BLOCK_SIZE)
	aes=AES.new(key, AES.MODE_CBC, iv)
	
	ct=iv+aes.encrypt(data)
	
	key2=SHA256.new(key).digest()
	
	return HMAC.new(key2, ct, SHA256).digest()+ct

def decrypt(data, key):
	
	if not len(data):
		print('no data to decrypt!')
		return None
	if not len(key):
		print('no decryption key!')
		return None
		
	key=str2key(key)
		
	hmac1=data[:32]
	ct=data[32:]
	
	key2=SHA256.new(key).digest()
	
	if not compare_digest(HMAC.new(key2, ct, SHA256).digest(), hmac1):
		print('hmac verification failed!')
		return None
	
	iv=ct[:BLOCK_SIZE]
	aes=AES.new(key, AES.MODE_CBC, iv)
	return unpad(aes.decrypt(ct[BLOCK_SIZE:]))
