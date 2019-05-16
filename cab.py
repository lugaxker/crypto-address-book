#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''

  Create a cryptocurrency address book using this script.
  
  This script is highly experimental. Do not use it to store large amounts.

'''

from crypto import *
from address import *
from constants import *

def get_account( mxprv, coin, i ):
    ''' Returns extended keys (private and public) of the account i (BIP-44).
        You have to specify the coin. '''
    if coin == "BCH":
        coin_type = Constants.BCH_BIP44_TYPE
    elif coin == "BTC":
        coin_type = Constants.BTC_BIP44_TYPE
    elif coin == "ETH":
        coin_type = Constants.ETH_BIP44_TYPE
    else:
        raise Exception( "this coin is not implemented: {}".format(coin) )
    branch = "m"
    sequence = "m/44'/{:d}'/{:d}'".format(coin_type, i)
    return private_derivation(mxprv, branch, sequence)


if __name__ == '__main__':
    
    mnemonic = ""
    seed = seed_from_mnemonic( mnemonic )
    mxprv, mxpub = root_from_seed( seed )
    for coin in SUPPORTED_COINS:
        xprv_acc, xpub_acc = get_account( mxprv, coin, 0 )
        branch = "m"
        sequence = "m/0/0"
        xpub = public_derivation(xpub_acc, branch, sequence)
        pubbytes, _, _, _, _ = decode_xkey(xpub)
        pubkey = PublicKey.from_ser( pubbytes )
        address = Address.from_pubkey(pubkey, coin)
        print( "{} address: {}".format(coin,address))
        
        