import binascii
import os
import time
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from secretsharing import PlaintextToHexSecretSharer
from secretsharing import SecretSharer


BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS).encode()
def unpad(s):
	# validate before trusting padding bytes; rejects wrong-key garbage
	if not s:
		raise ValueError('invalid padding')
	pad_len = s[-1]
	if pad_len < 1 or pad_len > BS:
		raise ValueError('invalid padding')
	if s[-pad_len:] != bytes([pad_len]) * pad_len:
		raise ValueError('invalid padding')
	return s[:-pad_len]

#GENERATE A (random hexadecimal number)
#temporaryKey = binascii.b2a_hex(os.urandom(16))

'''
Method:
	shamirs_split
Args:
	file object 
Function:
	This method splits the text content of the file using shamir's secret
	sharing algorithm. A list of hex codes are generated. These hex codes
	are later broken into three parts again. This list of list is returns
	as output
'''
def shamirs_split(file_object):
	text = file_object.read()
	list = PlaintextToHexSecretSharer.split_secret(text,2,2)
	hexcode = SecretSharer.split_secret(list[0][2:],2,2);
	return hexcode,list[1]

'''
Method:
	shamir's join
Args:
	list
Function:
	Converts the excrypted hexcodes into decrypted ones. Use those decrypted 
	hexcode to decrypt the text. Returns the text.
'''
def shamirs_join(list,str):
	temp = []
	msg_alpha =  SecretSharer.recover_secret(list[0:2])
	msg_alpha = '1-'+msg_alpha
	temp.append(msg_alpha)
	temp.append(str)
	text = PlaintextToHexSecretSharer.recover_secret(temp[0:2])
	return text

'''
Method:
	AES encryption
'''
def iv():
    """
    The initialization vector to use for encryption or decryption.
    It is ignored for MODE_ECB and MODE_CTR.
    """
    return chr(0) * 16

class AESCipher(object):

    def __init__(self, key):
        self.key = key
        #self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, message):
        """
        It is assumed that you use Python 3.0+
        , so plaintext's type must be str type(== unicode).
        """
        message = message.encode()
        raw = pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key.encode("utf8"), AES.MODE_CBC, iv)
        enc = iv + cipher.encrypt(raw)
        return base64.b64encode(enc).decode('utf-8')

    def decrypt(self, enc):
        try:
            enc = base64.b64decode(enc)
        except Exception:
            raise ValueError(
                'Decryption failed: the file is not a valid encrypted text file '
                '(expected base64 ciphertext)') from None
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key.encode("utf8"), AES.MODE_CBC, iv)
        dec = cipher.decrypt(enc[AES.block_size:])
        try:
            return unpad(dec).decode('utf-8')
        except Exception as exc:
            raise ValueError(
                'Decryption failed: the shared key does not match the key pair this file '
                'was encrypted for, or the ciphertext is corrupted') from None
