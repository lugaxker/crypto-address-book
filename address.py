#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from base58 import *
from crypto import (hash160, keccak256, PublicKey)
from constants import *

SUPPORTED_COINS = ["BCH", "BTC", "ETH"]

class AddressError(Exception):
    '''Exception used for Address errors.'''

class CashAddr:
    # Copyright (C) 2017 The Electron Cash Developers
    
    _CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    @staticmethod
    def _polymod(values):
        """Internal function that computes the cashaddr checksum."""
        c = 1
        for d in values:
            c0 = c >> 35
            c = ((c & 0x07ffffffff) << 5) ^ d
            if (c0 & 0x01):
                c ^= 0x98f2bc8e61
            if (c0 & 0x02):
                c ^= 0x79b76d99e2
            if (c0 & 0x04):
                c ^= 0xf33e5fb3c4
            if (c0 & 0x08):
                c ^= 0xae2eabe2a8
            if (c0 & 0x10):
                c ^= 0x1e4f43e470
        retval= c ^ 1
        return retval
    
    @staticmethod
    def _prefix_expand(prefix):
        """Expand the prefix into values for checksum computation."""
        retval = bytearray(ord(x) & 0x1f for x in prefix)
        # Append null separator
        retval.append(0)
        return retval
    
    @staticmethod
    def _create_checksum(prefix, data):
        """Compute the checksum values given prefix and data."""
        values = CashAddr._prefix_expand(prefix) + data + bytes(8)
        polymod = CashAddr._polymod(values)
        # Return the polymod expanded into eight 5-bit elements
        return bytes((polymod >> 5 * (7 - i)) & 31 for i in range(8))

    @staticmethod
    def _convertbits(data, frombits, tobits, pad=True):
        """General power-of-2 base conversion."""
        acc = 0
        bits = 0
        ret = bytearray()
        maxv = (1 << tobits) - 1
        max_acc = (1 << (frombits + tobits - 1)) - 1
        for value in data:
            acc = ((acc << frombits) | value ) & max_acc
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & maxv)

        if pad and bits:
            ret.append((acc << (tobits - bits)) & maxv)

        return ret

    @staticmethod
    def _pack_addr_data(kind, addr_hash):
        """Pack addr data with version byte"""
        version_byte = kind << 3

        offset = 1
        encoded_size = 0
        if len(addr_hash) >= 40:
            offset = 2
            encoded_size |= 0x04
        encoded_size |= (len(addr_hash) - 20 * offset) // (4 * offset)

        # invalid size?
        if ((len(addr_hash) - 20 * offset) % (4 * offset) != 0
                or not 0 <= encoded_size <= 7):
            raise ValueError('invalid address hash size {}'.format(addr_hash))

        version_byte |= encoded_size

        data = bytes([version_byte]) + addr_hash
        return CashAddr._convertbits(data, 8, 5, True)

    @staticmethod
    def _decode_payload(addr):
        """Validate a cashaddr string.

        Throws CashAddr.Error if it is invalid, otherwise returns the
        triple

        (prefix,  payload)

        without the checksum.
        """
        lower = addr.lower()
        if lower != addr and addr.upper() != addr:
            raise ValueError('mixed case in address: {}'.format(addr))

        parts = lower.split(':', 1)
        if len(parts) != 2:
            raise ValueError("address missing ':' separator: {}".format(addr))

        prefix, payload = parts
        if not prefix:
            raise ValueError('address prefix is missing: {}'.format(addr))
        if not all(33 <= ord(x) <= 126 for x in prefix):
            raise ValueError('invalid address prefix: {}'.format(prefix))
        if not (8 <= len(payload) <= 124):
            raise ValueError('address payload has invalid length: {}'
                            .format(len(addr)))
        try:
            data = bytes(CashAddr._CHARSET.find(x) for x in payload)
        except ValueError:
            raise ValueError('invalid characters in address: {}'
                                .format(payload))

        if CashAddr._polymod(CashAddr._prefix_expand(prefix) + data):
            raise ValueError('invalid checksum in address: {}'.format(addr))

        if lower != addr:
            prefix = prefix.upper()

        # Drop the 40 bit checksum
        return prefix, data[:-8]

    #
    # External Interface
    #

    PUBKEY_TYPE = 0
    SCRIPT_TYPE = 1

    @staticmethod
    def decode(address):
        '''Given a cashaddr address, return a triple

            (prefix, kind, hash)
        '''
        if not isinstance(address, str):
            raise TypeError('address must be a string')

        prefix, payload = CashAddr._decode_payload(address)

        # Ensure there isn't extra padding
        extrabits = len(payload) * 5 % 8
        if extrabits >= 5:
            raise ValueError('excess padding in address {}'.format(address))

        # Ensure extrabits are zeros
        if payload[-1] & ((1 << extrabits) - 1):
            raise ValueError('non-zero padding in address {}'.format(address))

        decoded = CashAddr._convertbits(payload, 5, 8, False)
        version = decoded[0]
        addr_hash = bytes(decoded[1:])
        size = (version & 0x03) * 4 + 20
        # Double the size, if the 3rd bit is on.
        if version & 0x04:
            size <<= 1
        if size != len(addr_hash):
            raise ValueError('address hash has length {} but expected {}'
                            .format(len(addr_hash), size))

        kind = version >> 3
        if kind not in (CashAddr.SCRIPT_TYPE, CashAddr.PUBKEY_TYPE):
            raise ValueError('unrecognised address type {}'.format(kind))

        return prefix, kind, addr_hash

    @staticmethod
    def encode(prefix, kind, addr_hash):
        """Encode a cashaddr address without prefix and separator."""
        if not isinstance(prefix, str):
            raise TypeError('prefix must be a string')

        if not isinstance(addr_hash, (bytes, bytearray)):
            raise TypeError('addr_hash must be binary bytes')

        if kind not in (CashAddr.SCRIPT_TYPE, CashAddr.PUBKEY_TYPE):
            raise ValueError('unrecognised address type {}'.format(kind))

        payload = CashAddr._pack_addr_data(kind, addr_hash)
        checksum = CashAddr._create_checksum(prefix, payload)
        return ''.join([CashAddr._CHARSET[d] for d in (payload + checksum)])

    @staticmethod
    def encode_full(prefix, kind, addr_hash):
        """Encode a full cashaddr address, with prefix and separator."""
        return ':'.join([prefix, CashAddr.encode(prefix, kind, addr_hash)])
    
def eth_checksum_encode( addr ): # hex address
    o = ''
    v = int.from_bytes( keccak256( addr.encode('utf-8') ), 'big')
    for i, c in enumerate( addr ):
        if c in '0123456789':
            o += c
        else:
            o += c.upper() if (v & (1 << (255 - 4*i))) else c.lower()
    return Constants.ETH_PREFIX + o
    
def eth_test_checksum( addr ): # hex address
    assert addr == eth_checksum_encode( addr[2:].lower() )

class Address:
    ''' Simple address derived from a public key, known as:
    - P2PKH in Bitcoin derivatives
    - EOA in Ethereum
    - Implicit account in Tezos '''
    
    def __init__(self, h, coin):
        assert len(h) == 20
        self.h = h
        assert coin in SUPPORTED_COINS
        self.coin = coin
    
    @classmethod
    def from_string(self, string):
        
        bch_prefix = Constants.BCH_HRP
        
        if (string.startswith(bch_prefix + ":q") or string.startswith("q")):
            
            if not string.startswith(bch_prefix + ':'):
                string = ':'.join([bch_prefix, string])
            addr_prefix, kind, addr_hash = CashAddr.decode(string)
            assert kind == 0
            if addr_prefix != bch_prefix:
                raise AddressError('address has unexpected prefix {}'
                                .format(addr_prefix))
            return self(addr_hash, "BCH")
        elif string.startswith("1"):
            vpayload = Base58.decode_check( string )
            verbyte, addr_hash = vpayload[0], vpayload[1:]
            assert verbyte == Constants.LEGACY_P2PKH
            return self(addr_hash, "BTC")
        elif string.startswith(Constants.ETH_PREFIX):
            if string.lower() != string: 
                eth_test_checksum(string)
            addr_hash = bytes.fromhex( string[2:].lower() )
            return self(addr_hash, "ETH")
        else:
            raise AddressError("cannot recognize address")
    
    @classmethod
    def from_pubkey(self, pubkey, coin):
        assert isinstance(pubkey, PublicKey)
        self.coin = coin
        if coin == "BCH":
            return self( hash160( pubkey.to_ser() ), coin)
        elif coin == "BTC":
            return self( hash160( pubkey.to_ser() ), coin)
        elif coin == "ETH":
            if pubkey.is_compressed():
                pubkey.uncompress()
            return self( keccak256( pubkey.to_ser()[1:] )[-20:], coin )
        else:
            AddressError("wrong coin")        
    
    def to_string(self):
        if self.coin == "BCH":
            return CashAddr.encode(Constants.BCH_HRP, 0, self.h)
        elif self.coin == "BTC":
            return Base58.encode_check(bytes([Constants.LEGACY_P2PKH]) + self.h)
        elif self.coin == "ETH":
            return eth_checksum_encode( self.h.hex() )
    
    def __str__(self):
        return self.to_string()

    def __repr__(self):
        return '<{} address {}>'.format(self.coin, self.to_string())
    
if __name__ == '__main__':
    
    bch_string = "qz954pyuatjtyrf654ud2k55ykr6n7yl9ql8cvc955"
    bch_string_2 = "bitcoincash:qz954pyuatjtyrf654ud2k55ykr6n7yl9ql8cvc955"
    btc_string = "1x6YnuBVeeE65dQRZztRWgUPwyBjHCA5g"
    eth_string = "0x83CbE1b588a7b1feBBF806b68Ac0c6Da9DeB69f7"
    eth_string_2 = "0x83cbe1b588a7b1febbf806b68ac0c6da9deb69f7"
    print()
    for string in [bch_string, bch_string_2, btc_string, eth_string, eth_string_2]:
        print("Original string", string)
        addr = Address.from_string(string)
        print("Address successfully created.")
        print("to_string result:", addr.to_string())
        print()
    print()
    
    K = PublicKey.from_ser("0283b0c52ec1204fcd3c309c76f5a8b544f76fcac21da65612978295f4497f5831")
    print("Public Key", K)
    for coin in SUPPORTED_COINS:
        addr = Address.from_pubkey( K, coin )
        print(addr)
    print()
    
