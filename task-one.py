import base64
from os import urandom

from Crypto.Cipher import AES

from Crypto.Cipher.AES import AESCipher
from Crypto.Util.py3compat import bchr, bord

SIZE = 16
# change this for either CBC or ECB
MODE = "CBC"
IVEC = urandom(16)


def main():
    byte_list, header = read_file("mustang.bmp")
    cipher: AESCipher = create_cipher_code()
    write_encrypted_file(cipher, byte_list, f"./mustang-{MODE}-encrypted.bmp", header)
    read_encrypted_file(cipher, f"./mustang-{MODE}-encrypted.bmp", f"mustang-{MODE}-unencrypted.bmp")


def create_cipher_code():
    return AES.new(urandom(16))


def write_encrypted_file(cipher: AESCipher, byte_list, out_file, header):
    with open(out_file, 'wb') as o:
        o.write(header)
        if MODE == "ECB":
            for byte_chunk in byte_list:
                padded = pad(byte_chunk)
                enc = cipher.encrypt(padded)
                o.write(enc)
        else:
            enc = encrypt_cbc(cipher, byte_list, IVEC)
            o.write(enc)

def read_encrypted_file(cipher: AESCipher, read_file, write_file):
    byte_list = []
    with open(read_file, 'rb') as r:
        header = r.read(54)
        byte = r.read(SIZE)
        while byte:
            if MODE == "ECB":
                byte = cipher.decrypt(byte)
                byte_list.append(byte)
                byte = r.read(SIZE)
            else:
                init_vec = IVEC
                byte, init_vec = decrypt_cbc(byte, cipher, init_vec)
                byte_list.append(byte)
                byte = r.read(SIZE)

        byte_list[-1] = unpad(byte_list[-1])

    with open(write_file, 'wb') as w:
        w.write(header)
        for b in byte_list:
            w.write(b)

def encrypt_cbc(ciper: AESCipher, byte_list, ivec):
    res = b''
    for block in byte_list:
        block = bytes(x ^ y for x, y in zip(block, ivec))
        enc = ciper.encrypt(pad(block))
        res += enc
        ivec = enc
    return res

def decrypt_cbc(ciphertext, cipher: AESCipher, ivec):
    result = b''
    before_xor = cipher.decrypt(ciphertext)
    pl = bytes(x ^ y for x, y in zip(before_xor, ivec))
    result += pl
    ivec = ciphertext
    return result, ivec


def split_plaintext(byte_array, mode):
    result = []
    num_blocks = len(byte_array) // SIZE
    for x in range(0, num_blocks):
        result.append(byte_array[x * SIZE: (x * SIZE) + SIZE])
    return result

def read_file(filename):
    res = []

    with open(filename, 'rb') as f:
        header = f.read(54)
        byte = f.read(SIZE)
        while byte:
            res.append(byte)
            byte = f.read(SIZE)

    return res, header

def pad(s):
    if len(s) == SIZE:
        return s
    padding_len = SIZE - len(s) % SIZE
    padding = bchr(padding_len) * padding_len
    return s + padding

def unpad(s):
    l = len(s)
    padding_len = bord(s[-1])
    return s[:-padding_len]


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
