"""
Provides to hashing-machines their underlying encoding-machine
"""

from pymerkle.exceptions import UnsupportedEncoding, UndecodableArgumentError

ENCODINGS = ['ascii', 'big5', 'big5hkscs', 'cp037', 'cp1026', 'cp1125',
    'cp1140', 'cp1250', 'cp1251', 'cp1252', 'cp1253', 'cp1254', 'cp1255',
    'cp1256', 'cp1257', 'cp1258', 'cp273', 'cp424', 'cp437', 'cp500', 'cp775',
    'cp850', 'cp852', 'cp855', 'cp857', 'cp858', 'cp860', 'cp861', 'cp862',
    'cp863', 'cp864', 'cp865', 'cp866', 'cp869', 'cp932', 'cp949', 'cp950',
    'euc_jis_2004', 'euc_jisx0213', 'euc_jp', 'euc_kr', 'gb18030', 'gb2312',
    'gbk', 'hp_roman8', 'hz', 'iso2022_jp', 'iso2022_jp_1', 'iso2022_jp_2',
    'iso2022_jp_2004', 'iso2022_jp_3', 'iso2022_jp_ext', 'iso2022_kr',
    'iso8859_10', 'iso8859_11', 'iso8859_13', 'iso8859_14', 'iso8859_15',
    'iso8859_16', 'iso8859_2', 'iso8859_3', 'iso8859_4', 'iso8859_5',
    'iso8859_6', 'iso8859_7', 'iso8859_8', 'iso8859_9', 'johab', 'koi8_r',
    'koi8_u', 'kz1048', 'latin_1', 'mac_cyrillic', 'mac_greek', 'mac_iceland',
    'mac_latin2', 'mac_roman', 'mac_turkish', 'ptcp154', 'shift_jis',
    'shift_jis_2004', 'shift_jisx0213', 'tis_620', 'utf_16', 'utf_16_be',
    'utf_16_le', 'utf_32', 'utf_32_be', 'utf_32_le', 'utf_7', 'utf_8',]
"""Supported encoding types"""


class Encoder(object):
    """
    Encapsulates the core encoding utility of hash-machines
    """
    def __init__(self, encoding='utf-8', raw_bytes=True, security=True):
        enc = encoding.lower().replace('-', '_')
        if enc not in ENCODINGS:
            err = f'Encoding type {encoding} is not supported'
            raise UnsupportedEncoding(err)
        self.encoding  = enc
        self.raw_bytes = raw_bytes
        self.security  = security

        self.encode = self.mk_encode_func()


    def mk_encode_func(self):
        """
        Constructs and returns the core utility of the present encoding machine
        in accordance with its initial configuration (*encoding type*,
        *raw-bytes* mode and *security* mode)
        """
        encoding = self.encoding

        # Resolve security prefices

        if self.security:
            prefix_0_dec, prefix_0_enc = '\x00', bytes('\x00', encoding)
            prefix_1_dec, prefix_1_enc = '\x01', bytes('\x01', encoding)
        else:
            prefix_0_dec, prefix_0_enc = '', bytes()
            prefix_1_dec, prefix_1_enc = '', bytes()

        # Make encoding funtion

        if self.raw_bytes:
            def encode_func(left, right=None):
                if not right:
                    if isinstance(left, bytes):
                        data = prefix_0_enc + left
                    else:
                        data = prefix_0_enc + bytes(left, encoding)
                else:
                    data = prefix_1_enc + left + prefix_1_enc + right
                return data
        else:
            def encode_func(left, right=None):
                if not right:
                    if isinstance(left, bytes):
                        try:
                            left_decoded = left.decode(encoding)
                        except UnicodeDecodeError:
                            raise UndecodableArgumentError
                        data = bytes(prefix_0_dec + left_decoded,
                            encoding=encoding)
                    else:
                        data = bytes(prefix_0_dec + left, encoding)
                else:
                    try:
                        left_decoded = left.decode(encoding)
                        right_decoded = right.decode(encoding)
                    except UnicodeDecodeError:
                        raise UndecodableArgumentError
                    data = bytes(prefix_1_dec + left_decoded +
                                 prefix_1_dec + right_decoded,
                            encoding=encoding)
                return data

        return encode_func
