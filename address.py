#!/usr/bin/env python3
# -*- coding: utf-8 -*-

SUPPORTED_COINS = ["BCH", "BTC", "ETH", "DSH", "XTZ"]

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
    
    def from_string(self, string):
        pass
    
    def from_pubkey(self, pubkey, coin):
        pass
    
    def to_string(self):
        pass
    
    def __str__(self):
        return self.to_string()

    def __repr__(self):
        return '<{} address {}>'.format(self.coin, self.to_string())
