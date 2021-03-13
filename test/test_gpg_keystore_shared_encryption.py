import os
import random
from unittest import TestCase

from git_anon.keystores.gpg_keystore_shared import SharedKeyStore, Padder


def random_folder():
    folder = "/tmp/" + str(random.randint(1, pow(10, 6)))
    os.makedirs(folder, exist_ok=True)
    return folder


class TestPadder(TestCase):

    def test_format(self):
        data = b"1234567890"
        padded = Padder(14).padd(data)
        self.assertEqual(padded[:4], bytes.fromhex("0a 00 00 00"))
        self.assertEqual(padded[4:], data)

        data = b"12345678"
        padded = Padder(14).padd(data)
        self.assertEqual(padded[:4], bytes.fromhex("08 00 00 00"))
        self.assertEqual(padded[4:], data + 2 * b"\00")

    def test_roundtrip(self):
        data = b"Just a simple teststring"
        padded = Padder(42).padd(data)
        unpadded = Padder(42).unpadd(padded)
        self.assertEqual(data, unpadded)


class TestSharedKeyStoreEncryption(TestCase):
    secret = "secret"
    params_file_content = [
        "algo: pbkdf2\n"
        "scrypt_n: 2\n",
        "scrypt_r: 4\n",
        "scrypt_p: 1\n",
        "salt: c32627d57fd76b0ddca525d7d8ce4b4bbc22eba8c091a54453c97e4e3fec06be\n"
        "hash: 73ebc3d72fc65109e2614584d2048052abc61f809af335f5eafed647c97fbc30\n"
    ]
    nonce = "my_nonce_1234567890_1234567890"
    plaintext = bytes("123", 'utf-8')
    ciphertext = (
        b'\xf6\xc7\xe3\x08\xfd\xfc\x06k\xf98\x8a\xc6\xb9\xab\x83\x1b\x00(\n\x0f'
        b'\xdf\xcf.\xb3\xef\x80\xe9@ =\x10\xc8\xff\x1c\x9e\x05ag\xab*\xa9\x94\xe2Q'
        b'\xef\xb2\x96c\xe3\x19\xa0\xc0\x83\x8e\x10\xb4\xa0}\xf4\x1b\xd6\xc5F\xd0'
        b'\x87\n\xbf1\x02\xe3\xd6\xe1\xc3\xe6\xf7\xea\x1c\x84\x00x(\xe5\xf2S\xd3Nq\xbc'
        b'\xff/\x11`\x8bg\xe3\\\x14\xa9X\xb6\xe7i\x94\xba\xbf\xc5u;\x86\x088z'
        b't\xa6\xccDE\x7f\xd2SHj\xa1L\x14\x12\x0e[\xa3\x00\xcf&\x9f\xa4L\xd6'
        b'\x932\xc2\x1f\xb8\xce\n\xe9\xb3\xe74\xfbC\tL\xd6&>\x86\x7fP\xe8\xd2n'
        b'@\xe9\xec\xc1c\xaa\x0c\xab\xfdz)\x99R\xa7\xd0v\x08\xed)\xb0()\xab\x9c\x003>h'
        b'i\xb9\xdb\x988Qb ;\x93\xb5I\xeeN\x1e\x96\x84\xc8^\xfc\xf3jF\xe4x\xa1\xe7\xf2'
        b'\xb0u\xc0\xe3Q\xe2\xd2\x02\x9c\x7fH\xb1\x15\x7f\xc8ho\n]\x18;\x14BM'
        b'\xbe\xde\xe6\xa7K\x92\xfbSh\xe9\x04\x1e\xc15\xdb\xb8\x02\x7f\x88]'
        b'\x9bu\x0e\xaa\x16h\xa3R;\x19`r\xf8K[\x80\x92\xc77\x9e\xcf\x8f\x06\x93'
        b'\xb9\xb8?<\xea\xdf\t\xce\x17\xa9\x11\xb37\xf7/\xb3|\xf3\x9ap*\xaf\xf4\xe1'
        b'\x0e\xb1\x00t\xf0\xff\xe7\xd5\xf8\xe9\xd7\xc0\xa9\xdfb<eFx\n\x05\xd5\xc0\xdf'
        b'\x13\xaf\xd9]\xbc\x95\xb0\xe0\n\xaaOK\xbd3\x91\x06\xa56\x9c\xe9\xe6>\x03\x90'
        b'\x13\xafX\xdf\xae\xa4\x16\xd3\x95\xc9:\x127\xa7\x1f\xae}\xd4U_\x18P\xa6\xb8'
        b'\x0c\x9anZ8-h}Y\xb8\x9c\x15\x06=\xa1__\x17#\x8a\xf4w\x13\x18\x0c\x90x&'
        b'U\x06\x9bi\xa1\xaf%\x04O9;^P|\xcc\xef\xb6\xd4x\xdf\xd1\xddL\xfe\xffk\x07='
        b'{3\xe3\x93S\xac\xa7^\xaec\x95\xdc\x93\x1c\xa7\x8d\xc7\xa7(\xd2:\x95\xc1\x0c'
        b'n\xbd!\x97=\xaf\xef\x92epn\xedP8\xd5\xb9O\xf6,\x7f\x18}\xd3\x854\x1e\nk'
        b'\xf1\x89@\x0e\xd1\x9f\xc3_S\xaa\xc5\x99\x11s(\xb2\xbf%p\x81e,\r<'
    )

    def test_encryption(self):
        folder = random_folder()
        with open(folder + "/enc_params", "w") as file:
            file.writelines(self.params_file_content)
        keystore = SharedKeyStore(folder, folder, self.secret)
        ciphertext = keystore._encrypt_bytes(self.plaintext, self.nonce)

        self.assertEqual(len(ciphertext), 512)
        self.assertEqual(ciphertext, self.ciphertext)

    def test_decryption(self):
        folder = random_folder()
        with open(folder + "/enc_params", "w") as file:
            file.writelines(self.params_file_content)
        keystore = SharedKeyStore(folder, folder, self.secret)
        plaintext = keystore._decrypt_bytes(self.ciphertext, self.nonce)

        self.assertEqual(plaintext, self.plaintext)
