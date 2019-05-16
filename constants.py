#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class Constants:
    '''Network constants.'''
    
    XPRV_HEADER = 0x0488ade4
    XPUB_HEADER = 0x0488b21e
    BIP32_HARDENED = 0x80000000
    
    # Bitcoin
    WIF_PREFIX = 0x80
    LEGACY_P2PKH = 0x00
    LEGACY_P2SH = 0x05
    
    # BCH
    BCH_BIP44_TYPE = 0x91
    BCH_HRP = "bitcoincash"
    
    # BTC
    BTC_BIP44_TYPE = 0x00
    
    # ETH
    ETH_BIP44_TYPE = 0x3c
    ETH_PREFIX = "0x"
    
    # DSH
    DSH_BIP44_TYPE = 0x05
    DSH_WIF_PREFIX = 0xcc
    DSH_P2PKH = 0x4c
    DSH_P2SH = 0x10
    
    # XTZ
    XTZ_BIP44_TYPE = 0x06c1
    
    
    
