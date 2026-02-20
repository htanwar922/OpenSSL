#!/usr/bin/python3

# pylint: disable=invalid-name,missing-docstring,unused-import,unused-variable,unused-argument,line-too-long
# pylint: disable=too-many-locals,unnecessary-pass,pointless-string-statement,using-constant-test
# pylint: disable=multiple-statements,logging-fstring-interpolation,multiple-imports,wrong-import-position
# pylint: disable=import-outside-toplevel,unnecessary-lambda-assignment
# pylint: disable=consider-using-f-string,redefined-outer-name,global-statement,broad-except

import sys
import ctypes

if sys.platform == 'win32':
    libc = ctypes.CDLL('msvcrt.dll')    # Windows
else:
    libc = ctypes.CDLL(None)            # Use default C library on Linux/macOS
stdout = libc.fdopen(1, b'w')           # FILE* for stdout

libssl = ctypes.cdll.LoadLibrary('libssl.so')  # Change to 'libssl.dylib' on macOS or 'libssl-3.dll' on Windows

AES_BLOCK_SIZE = 16

ERR_LIB_NONE            = 1

EVP_CTRL_GCM_SET_IVLEN  = 0x9
EVP_CTRL_GCM_GET_TAG    = 0x10
EVP_CTRL_GCM_SET_TAG    = 0x11

EVP_get_cipherbyname = libssl.EVP_get_cipherbyname
EVP_get_cipherbyname.restype = ctypes.c_void_p
EVP_get_cipherbyname.argtypes = [ctypes.c_char_p]

EVP_EncryptInit_ex = libssl.EVP_EncryptInit_ex
EVP_EncryptInit_ex.restype = ctypes.c_int
EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

EVP_CIPHER_CTX_new = libssl.EVP_CIPHER_CTX_new
# EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
# EVP_CIPHER_CTX_new.argtypes = []

EVP_CIPHER_CTX_ctrl = libssl.EVP_CIPHER_CTX_ctrl
EVP_CIPHER_CTX_ctrl.restype = ctypes.c_int
EVP_CIPHER_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]

EVP_EncryptUpdate = libssl.EVP_EncryptUpdate
EVP_EncryptUpdate.restype = ctypes.c_int
EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]

EVP_EncryptFinal_ex = libssl.EVP_EncryptFinal_ex
EVP_EncryptFinal_ex.restype = ctypes.c_int
EVP_EncryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

EVP_CIPHER_CTX_free = libssl.EVP_CIPHER_CTX_free
EVP_CIPHER_CTX_free.restype = None
EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]

BIO_new_fp = libssl.BIO_new_fp
BIO_new_fp.restype = ctypes.c_void_p
BIO_new_fp.argtypes = [ctypes.c_int, ctypes.c_int]

BIO_free = libssl.BIO_free
BIO_free.restype = None
BIO_free.argtypes = [ctypes.c_void_p]

BIO_printf = libssl.BIO_printf
BIO_printf.restype = ctypes.c_int
BIO_printf.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

BIO_dump_fp = libssl.BIO_dump_fp
BIO_dump_fp.restype = ctypes.c_int
BIO_dump_fp.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]

def create_ctypes_buffer(data, which = 'ubyte'):
    if which == 'ubyte':
        return (ctypes.c_ubyte * len(data)).from_buffer(data)
    if which == 'char':
        return ctypes.create_string_buffer(bytes(data))
    if which == 'char_p':
        return ctypes.c_char_p(data)
    return None

class AES:
    def __init__(self, key, mode = 'GCM'):
        self.mode = mode
        self.key = create_ctypes_buffer(key)

    def _encrypt(self, ctx, _plaintext, _ciphertext, _iv, _tag, _aad):
        ret = EVP_EncryptInit_ex(ctx, EVP_get_cipherbyname(b'AES-128-GCM'), None, None, None)
        if ret != ERR_LIB_NONE:
            print('EVP_EncryptInit error')
            return None
        if self.mode == 'GCM':
            ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(_iv), None)
            if ret != ERR_LIB_NONE:
                print('EVP_CIPHER_CTX_ctrl error in setting the IV Length')
                return None
        ret = EVP_EncryptInit_ex(ctx, None, None, self.key, _iv)
        if ret != ERR_LIB_NONE:
            print('EVP_EncryptInit error')
            return None
        if _aad and len(_aad):
            _aad_len = len(_aad)
            _aad_len_ptr = ctypes.byref(ctypes.c_int(_aad_len))
            ret = EVP_EncryptUpdate(ctx, None, _aad_len_ptr, _aad, _aad_len)
            if ret != ERR_LIB_NONE:
                print('EVP_EncryptUpdate error in setting the AAD')
                return None
        retLength1 = ctypes.c_int(0)
        ret = EVP_EncryptUpdate(ctx, _ciphertext, ctypes.byref(retLength1), _plaintext, len(_plaintext))
        if ret != ERR_LIB_NONE:
            print('EVP_EncryptUpdate error')
            return None
        retLength2 = ctypes.c_int(0)
        ret = EVP_EncryptFinal_ex(ctx, ctypes.byref(_ciphertext, retLength1.value), ctypes.byref(retLength2))
        if ret != ERR_LIB_NONE:
            print('EVP_EncryptFinal error')
            return None
        if self.mode == 'GCM':
            if _tag and len(_tag):
                ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, len(_tag), _tag)
                if ret != ERR_LIB_NONE:
                    print('EVP_CIPHER_CTX_ctrl error in getting the tag')
                    return None
            else:
                print('Tag length is zero or tag is NULL')
        return retLength1.value + retLength2.value

    def _decrypt(self, ctx, _ciphertext, _plaintext, _iv, _tag, _aad):
        ret = EVP_EncryptInit_ex(ctx, EVP_get_cipherbyname(b'AES-128-GCM'), None, None, None)
        if ret != ERR_LIB_NONE:
            print('EVP_EncryptInit error')
            return None
        if self.mode == 'GCM':
            ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(_iv), None)
            if ret != ERR_LIB_NONE:
                print('EVP_CIPHER_CTX_ctrl error in setting the IV Length')
                return None
        ret = EVP_EncryptInit_ex(ctx, None, None, self.key, _iv)
        if ret != ERR_LIB_NONE:
            print('EVP_EncryptInit error')
            return None
        if _aad and len(_aad):
            _aad_len = len(_aad)
            _aad_len_ptr = ctypes.byref(ctypes.c_int(_aad_len))
            ret = EVP_EncryptUpdate(ctx, None, _aad_len_ptr, _aad, _aad_len)
            if ret != ERR_LIB_NONE:
                print('EVP_EncryptUpdate error in setting the AAD')
                return None
        retLength1 = ctypes.c_int(0)
        ret = EVP_EncryptUpdate(ctx, _plaintext, ctypes.byref(retLength1), _ciphertext, len(_ciphertext))
        if ret != ERR_LIB_NONE:
            print('EVP_EncryptUpdate error')
            return None
        retLength2 = ctypes.c_int(0)
        ret = EVP_EncryptFinal_ex(ctx, ctypes.byref(_plaintext, retLength1.value), ctypes.byref(retLength2))
        if ret != ERR_LIB_NONE:
            print('EVP_EncryptFinal error')
            return None
        if self.mode == 'GCM':
            if _tag and len(_tag):
                ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, len(_tag), _tag)
                if ret != ERR_LIB_NONE:
                    print('EVP_CIPHER_CTX_ctrl error in getting the tag')
                    return None
            else:
                print('Tag length is zero or tag is NULL')
        return retLength1.value + retLength2.value

    def encrypt(self, plaintext, ciphertext, iv, tag = None, aad = None) -> bytearray:
        _plaintext  = create_ctypes_buffer(plaintext)
        _iv         = create_ctypes_buffer(iv)
        _ciphertext = create_ctypes_buffer(ciphertext) if ciphertext else ctypes.c_void_p(None)
        _tag        = create_ctypes_buffer(tag) if tag else ctypes.c_void_p(None)
        _aad        = create_ctypes_buffer(aad) if aad else ctypes.c_void_p(None)
        ctx = EVP_CIPHER_CTX_new()
        ret = self._encrypt(ctx, _plaintext, _ciphertext, _iv, _tag, _aad)
        EVP_CIPHER_CTX_free(ctx)
        if ret is None:
            return None
        ciphertext[:] = _ciphertext
        tag[:] = _tag
        return ret

    def decrypt(self, ciphertext, plaintext, iv, tag = None, aad = None) -> bytearray:
        _ciphertext = create_ctypes_buffer(ciphertext)
        _iv         = create_ctypes_buffer(iv)
        _plaintext  = create_ctypes_buffer(plaintext) if plaintext else ctypes.c_void_p(None)
        _tag        = create_ctypes_buffer(tag) if tag else ctypes.c_void_p(None)
        _aad        = create_ctypes_buffer(aad) if aad else ctypes.c_void_p(None)
        ctx = EVP_CIPHER_CTX_new()
        ret = self._decrypt(ctx, _ciphertext, _plaintext, _iv, _tag, _aad)
        EVP_CIPHER_CTX_free(ctx)
        if ret is None:
            return None
        plaintext[:] = _plaintext
        return ret

if __name__ == '__main__':
    bio_out = BIO_new_fp(stdout, 0)

    KEY = bytearray.fromhex('000102030405060708090a0b0c0d0e0f')
    AAD = bytearray.fromhex('00' + 'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf')
    AAD[0] = 0x30
    IV = bytearray.fromhex('4142434445464748') + int(20).to_bytes(4, 'big')

    aes = AES(KEY)

    plaintext = bytearray([0x01, 0x01, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
        0xdd, 0xee, 0xff, 0x00, 0x00, 0x06, 0x5f, 0x1f,
        0x04, 0x00, 0x00, 0x7e, 0x1f, 0x04, 0xb0,])

    ciphertext = bytearray(len(plaintext))
    decodedtext = bytearray(len(plaintext))
    tag = bytearray(12)

    ret = aes.encrypt(plaintext, ciphertext, IV, tag, AAD)
    if ret is None:
        print('Encryption failed')

    ret = aes.decrypt(ciphertext, decodedtext, IV, tag, AAD)
    if ret is None:
        print('Decryption failed')

    BIO_printf(bio_out, b'Plaintext is:\n')
    BIO_dump_fp(stdout, bytes(plaintext), len(plaintext))
    BIO_printf(bio_out, b'Key is:\n')
    BIO_dump_fp(stdout, bytes(KEY), len(KEY))
    BIO_printf(bio_out, b'IV is:\n')
    BIO_dump_fp(stdout, bytes(IV), len(IV))
    BIO_printf(bio_out, b'Ciphertext is:\n')
    BIO_dump_fp(stdout, bytes(ciphertext), len(ciphertext))
    BIO_printf(bio_out, b'Tag is:\n')
    BIO_dump_fp(stdout, bytes(tag), len(tag))
    BIO_printf(bio_out, b'Decodedtext is:\n')
    BIO_dump_fp(stdout, bytes(decodedtext), len(decodedtext))
