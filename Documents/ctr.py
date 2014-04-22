from Crypto.Cipher import AES, XOR  # from pycrypto library (https://www.dlitz.net/software/pycrypto/)
 
 
block_size = AES.block_size
 
 
def decrypt(key, ciphertext):
    # assume: len(key) == len(IV) == 16 bytes; no padding
    iv = ciphertext[:block_size]
    ciph = ciphertext[block_size:]
 
    cipher = AES.new(key)
    ivn = int(iv.encode('hex'), 16) # the IV string in numeric form
    plain_blocks = []
    i = 0
    while True:
        ciph_block = ciph[(i*block_size):((i+1)*block_size)]
        if not ciph_block:      # the last iteration was the last block
            # calculate junk "padding" length
            last_ciph_block = ciph[((i-1)*block_size):]
            last_ciph_block_len = len(last_ciph_block)
            # and remove that many junk bytes from the last plain text block
            last_plain_block = plain_blocks[-1]
            plain_blocks[i-1] = last_plain_block[:last_ciph_block_len]
            # then break out of this loop, we are done
            break
        xor = XOR.new(ciph_block)
 
        # calculate the IV + i for this block in byte string
        iv = hex(ivn + i)[2:]   # add i to IV, then convert to hex (removing the '0x' prefix)
        if iv[-1] == 'L':       # remove 'L' suffix in python's hex representation string
            iv = iv[:-1]
        if len(iv) < 16:        # prepend zeroes if the hex string is < 16 bytes
            iv = '0' * (16 - len(iv)) + iv
        iv = iv.decode('hex')   # convert again the hex string into byte string
 
        plain_block = xor.decrypt(cipher.encrypt(iv))   # encrypt the modified IV, then XOR with cipher block
 
        i += 1
        plain_blocks.append(plain_block)
 
    return ''.join(plain_blocks)
 
 
if __name__ == '__main__':
    keys_ciphertexts_hex = [
            ('36f18357be4dbd77f050515c73fcf9f2', '69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329'),
            ('36f18357be4dbd77f050515c73fcf9f2', '770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451'),
            ]
 
    for key_hex, ciphertext_hex in keys_ciphertexts_hex:
        key = key_hex.decode('hex')
        ciphertext = ciphertext_hex.decode('hex')
 
        print repr(decrypt(key, ciphertext))
