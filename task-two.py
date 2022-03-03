import sys
from operator import xor

from Crypto.Cipher import AES
from os import urandom

from Crypto.Cipher.AES import AESCipher
from Crypto.Util.py3compat import bchr, bord

SIZE = 16
ENCRYPTION = 1
SUBMISSION = ";admin=true"


def main():
    cipher = AES.new(urandom(16))
    ivec = urandom(16)
    ciphertext = submit(SUBMISSION, cipher, ivec)
    flipped_ciphertext = flip_byte(ciphertext)

    decrypted_flipped = decrypt(flipped_ciphertext, cipher, ivec)
    decrypted = decrypt(ciphertext, cipher, ivec)
    print(f"Decrypted: {decrypted}")
    print(f"Flipped Decrypted: {decrypted_flipped}")


def flip_byte(ciphertext):
    blocks = split_plaintext(ciphertext, 0)

    # TODO: find how many bytes are taken with prepending the server data
    prepend = bytes("userid=456;userdata=".encode())
    preceding_bytes = len(prepend)

    # TODO: identify which block has to be targeted based on size of prepend
    target_block_idx = (preceding_bytes // SIZE) - 1
    payload_byte_idx_eq = preceding_bytes % SIZE + (len(bytes("admin".encode())) + 1)
    payload_byte_idx_semi = preceding_bytes % SIZE + (len(bytes("".encode())))
    targets = [payload_byte_idx_eq, payload_byte_idx_semi]
    exp_target_char = ["=", ";"]


    # TODO: insert the "=" sign
    target_block = blocks[target_block_idx]
    b_list = list(target_block)


    # QUESTION:
    # how do i simply change this without destroying the chain?
    # is it more complicated once I am trying to replace %20?
    for target, char in zip(targets, exp_target_char):
        b_list[target] = b_list[target] ^ ord("-") ^ ord(char)
    print(blocks)
    blocks[target_block_idx] = bytes(b_list)
    return b"".join(blocks)


def verify(ciphertext: bytes, cipher, ivec):
    unencrypted = decrypt(ciphertext, cipher, ivec).decode("utf-8")
    return ";admin=true;" in unencrypted


def decrypt(ciphertext, cipher: AESCipher, ivec):
    result = b''
    blocks = split_plaintext(ciphertext, 0)
    idx = 0
    for block in blocks:
        before_xor = cipher.decrypt(block)
        pl = bytes(x ^ y for x, y in zip(before_xor, ivec))
        if idx == len(blocks) - 1:
            pl = unpad(pl)
        result += pl
        ivec = block
        idx += 1
    return result


def submit(string: str, cipher: AESCipher, ivec):
    if "=" in string:
        string = string.replace("=", "-", string.count("="))
    if ";" in string:
        string = string.replace(";", "-", string.count(";"))

    res = "userid=456;userdata=" + string + ";session-id=31337"
    byte = str.encode(res)
    byte_list = split_plaintext(byte, 1)
    enc = encrypt(cipher, byte_list, ivec)
    return enc


def encrypt(ciper: AESCipher, byte_list, ivec):
    res = b''
    for block in byte_list:
        block = bytes(x ^ y for x, y in zip(block, ivec))
        enc = ciper.encrypt(block)
        res += enc
        ivec = enc
    return res


def split_plaintext(byte_array, mode):
    result = []
    num_blocks = len(byte_array) // SIZE
    for x in range(0, num_blocks):
        result.append(byte_array[x * SIZE: (x * SIZE) + 16])
    last_pos = num_blocks * SIZE
    if mode == ENCRYPTION:
        result.append(pad(byte_array[last_pos:]))
    return result


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


if __name__ == '__main__':
    main()
