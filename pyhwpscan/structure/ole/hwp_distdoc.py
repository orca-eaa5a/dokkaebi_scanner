from structure.hwp.hwp_record import HWPDistDocRecord
from io import BytesIO
from Crypto.Cipher import AES

class Random:
    ''' MSVC's srand()/rand() like pseudorandom generator.
    '''

    def __init__(self, seed):
        self.seed = seed

    def rand(self):
        self.seed = (self.seed * 214013 + 2531011) & 0xffffffff
        value = (self.seed >> 16) & 0x7fff
        return value


def decode_head_to_sha1(record_payload):
    ''' Decode HWPTAG_DISTRIBUTE_DOC_DATA.
    It's the sha1 digest of user-supplied password string, i.e.,
        '12345' -> hashlib.sha1('12345').digest()
    '''
    if len(record_payload) != 256:
        raise ValueError('payload size must be 256 bytes')

    data = bytearray(record_payload)
    seed = data[3] << 24 | data[2] << 16 | data[1] << 8 | data[0]
    random = Random(seed)

    n = 0
    for i in range(256):
        if n == 0:
            key = random.rand() & 0xff
            n = (random.rand() & 0xf) + 1
        if i >= 4:
            data[i] = data[i] ^ key
        n -= 1

    # decoded = b''.join(chr(x) for x in data)
    decoded = data
    sha1offset = 4 + (seed & 0xf)

    ucs16le = decoded[sha1offset:sha1offset + 80]
    return ucs16le


def decode_head_to_key(record_payload):
    sha1ucs16le = decode_head_to_sha1(record_payload)
    return bytes(sha1ucs16le[:16])


def aes128ecb_decrypt(key, encrypted_data):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(encrypted_data)

def decrypt_distdoc(stream:BytesIO):
    dist_doc_record = HWPDistDocRecord()
    dist_doc_record.parse(stream)
    if dist_doc_record.header.tag_id != 28: # HWPTAG_DISTRIBUTION_DOC
        raise Exception("unknown file type...")
    distdoc_data = dist_doc_record.payload
    key = decode_head_to_key(distdoc_data)
    encrypted_data = stream.read()
    decrypted = aes128ecb_decrypt(key, encrypted_data)
    return decrypted