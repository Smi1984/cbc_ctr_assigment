from Crypto.Cipher import AES, XOR  # from pycrypto library (https://www.dlitz.net/software/pycrypto/)
from Crypto.Util import Counter
 
 
def decrypt(key, ciphertext):
    iv = ciphertext[:16]
    ciph = ciphertext[16:]
    ctr = Counter.new(128,initial_value = int(iv.encode('hex'), 16))
    cipher = AES.new(key1, AES.MODE_CTR, counter=ctr )
    print cipher.decrypt(ciph)
	
	
	 
 
if __name__ == '__main__':

    key1 = '36f18357be4dbd77f050515c73fcf9f2'.decode('hex')
    ciphertext = '69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329'.decode('hex')
    ciphertext2 = '770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451'.decode('hex')
 
    decrypt(key1,ciphertext)
    decrypt(key1,ciphertext2)
