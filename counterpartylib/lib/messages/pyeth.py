#! /usr/bin/python3

from counterpartylib.lib import util
from counterpartylib.lib import config
from counterpartylib.lib import log
from counterpartylib.lib import script

import logging
logger = logging.getLogger(__name__)
import pickle
import binascii
import string

def hexprint(x):
    assert type(x) in (bytes, list)
    if not x:
        return '<None>'
    if x != -1:
        return ('0x' + util.hexlify(bytes(x)))
    else:
        return 'OUT OF GAS'

# TODO  GAS COSTS, CONSTANTS

def convert(address):
    """Convert a Bitcoin address from `bytes` to `str`.

    Pass Bitcoin addresses to Ethereum VM as bytes, so that they may be
    RLP‐encoded.
    """
    # NOTE: HACK?

    if address == '3kbQ7ZT62PAgeNQBTixJHqn7Hopj4pQc5MGFqRapKN8ecEGSjJBWJUT5GgP5Be':
        raise Exception

    assert address
    if type(address) == bytes:
        address_bytes = address
        address_hex = binascii.hexlify(address_bytes).decode('ascii')
        address_str = script.base58_check_encode(address_hex, config.ADDRESSVERSION)

        assert type(address_str) == str
    else:
        address_str = address
        if all(c in string.hexdigits for c in address_str):
            # Ethereum address string.
            return address_str
        else:
            # Bitcoin address string.
            script.validate(address_str)

    return address_str

class Block(object):

    def __init__(self, db, block_index):
        self.db = db

        cursor = db.cursor()
        block = list(cursor.execute('''SELECT * FROM blocks WHERE block_index= ?''', (block_index,)))[0]
        self.block_hash = block['block_hash']
        self.timestamp = block['block_time']
        self.number = block['block_index']
        self.prevhash = block['previous_block_hash']
        self.difficulty = block['difficulty']
        self.gas_used = int(block['gas_used'])  # TODO: `int()` temporary
        self.gas_limit = int(block['gas_limit'])    # TODO: `int()` temporary
        self.refunds = int(block['gas_limit'])    # TODO: `int()` temporary
        cursor.execute('''DELETE FROM suicides''')
        self.suicides = self.suicides_get()
        self.coinbase = 'COINBASE'  # TODO

        return

    def snapshot(self): # TODO
        return  # TODO

    def add_transaction_to_list(self, tx): # TODO
        return  # TODO

    def revert(self, snapshot):
        # TODO
        # TODO
        return

    def commit_state(self):
        # TODO
        # TODO
        return

    def refunds(self):
        # TODO
        # TODO
        return

    def set_code (self, to, dat):
        # TODO
        # TODO
        return

    def set_balance(self, address):
        address = convert(address)
        return

    def postqueue_delete(self):
        cursor = self.db.cursor()
        cursor.execute('''DELETE FROM postqueue''')

    def postqueue_insert(self, message):
        cursor = self.db.cursor()
        cursor.execute('''INSERT INTO postqueue VALUES(:message)''', {'message': pickle.dumps(message)})

    def postqueue_get(self):
        cursor = self.db.cursor()
        return list(cursor.execute('''SELECT * FROM postqueue'''))

    def postqueue_append(self, post_msg):
        cursor = self.db.cursor()
        cursor.execute('''INSERT INTO postqueue VALUES(:message)''', {'message': pickle.dumps(post_msg)})

    def postqueue_pop(self):
        cursor = self.db.cursor()
        postqueues = list(cursor.execute('''SELECT * FROM postqueue ORDER BY rowid ASC'''))
        first_message_pickled = postqueues[0]['message']                                                # Get first entry.
        cursor.execute('''DELETE FROM postqueue WHERE rowid = (SELECT MIN(rowid) FROM postqueue)''')    # Delete first entry.
        return pickle.loads(first_message_pickled)


    def suicides_append(self, contract_id):
        cursor = self.db.cursor()
        cursor.execute('''INSERT INTO suicides VALUES(:contract_id)''', {'contract_id': contract_id})

    def suicides_get(self):
        cursor = self.db.cursor()
        self.suicides = list(cursor.execute('''SELECT * FROM suicides'''))
        return self.suicides

    def suicides_delete(self):
        cursor = self.db.cursor()
        cursor.execute('''DELETE FROM suicides''')

    def get_storage_data(self, contract_id, key=None):
        cursor = self.db.cursor()

        if key == None:
            cursor.execute('''SELECT * FROM storage WHERE contract_id = ? ''', (contract_id,))
            storages = list(cursor)
            return storages

        # print('prekey', key)
        key = key.to_bytes(32, byteorder='big')
        cursor.execute('''SELECT * FROM storage WHERE contract_id = ? AND key = ?''', (contract_id, key))
        storages = list(cursor)
        # print('key', key)
        if not storages:
            return 0
        value = storages[0]['value']

        import pyethereum.rlp
        value = pyethereum.rlp.big_endian_to_int(value)
        return value

    def set_storage_data(self, contract_id, key, value):
        # NOTE: This could all be done more elegantly, I think.

        key = key.to_bytes(32, byteorder='big')
        value = value.to_bytes(32, byteorder='big')

        cursor = self.db.cursor()
        cursor.execute('''SELECT * FROM storage WHERE contract_id = ? AND key = ?''', (contract_id, key))
        storages = list(cursor)
        if storages:    # Update value.
            bindings = {
                'contract_id': contract_id,
                'key': key,
                'value': value
                }
            log.message(self.db, self.number, 'update', 'storage', bindings)
            sql='''UPDATE storage SET value = :value WHERE contract_id = :contract_id AND key = :key'''
            cursor.execute(sql, bindings)
        else:           # Insert value.
            bindings = {
                'contract_id': contract_id,
                'key': key,
                'value': value
                }
            log.message(self.db, self.number, 'insert', 'storage', bindings)
            sql='''INSERT INTO storage VALUES (:contract_id, :key, :value)'''
            cursor.execute(sql, bindings)

        storages = cursor.execute('''SELECT * FROM storage WHERE contract_id = ? AND key = ?''', (contract_id, key))

        return value


    def account_to_dict(self, address):
        address = convert(address)
        return {'nonce': Block.get_nonce(self, address), 'balance': Block.get_balance(self, address), 'storage': Block.get_storage_data(self, address), 'code': hexprint(Block.get_code(self, address))}

    def get_code (self, contract_id):
        cursor = self.db.cursor()
        cursor.execute('''SELECT * FROM contracts WHERE contract_id = ?''', (contract_id,))
        contracts = list(cursor)

        if not contracts:
            return b''
        else: code = contracts[0]['code']

        return code

    def get_nonce(self, address):
        address = convert(address)
        cursor = self.db.cursor()
        nonces = list(cursor.execute('''SELECT * FROM nonces WHERE (address = ?)''', (address,)))
        if not nonces: return 0
        else: return nonces[0]['nonce']

    def set_nonce(self, address, nonce):
        address = convert(address)
        cursor = self.db.cursor()
        cursor.execute('''SELECT * FROM nonces WHERE (address = :address)''', {'address': address})
        nonces = list(cursor)
        bindings = {'address': address, 'nonce': nonce}
        if not nonces:
            log.message(self.db, self.number, 'insert', 'nonces', bindings)
            cursor.execute('''INSERT INTO nonces VALUES(:address, :nonce)''', bindings)
        else:
            log.message(self.db, self.number, 'update', 'nonces', bindings)
            cursor.execute('''UPDATE nonces SET nonce = :nonce WHERE (address = :address)''', bindings)

    def increment_nonce(self, address):
        address = convert(address)
        nonce = Block.get_nonce(self, address)
        Block.set_nonce(self, address, nonce + 1)

    def decrement_nonce(self, address):
        address = convert(address)
        nonce = Block.get_nonce(self, address)
        Block.set_nonce(self, address, nonce - 1)

    def get_balance(self, address, asset=config.XCP):
        address = convert(address)
        return util.get_balance(self.db, address, asset)

    def transfer_value(self, source, destination, quantity, asset=config.XCP):
        if source != self.coinbase:
            source = convert(source)
            util.debit(self.db, source, asset, quantity, action='transfer value', event=self.block_hash)
        if destination != self.coinbase:
            destination = convert(destination)
            util.credit(self.db, destination, asset, quantity, action='transfer value', event=self.block_hash)
        return True

    def del_account(self, contract_id):
        cursor = self.db.cursor()
        logger.debug('SUICIDING {}'.format(contract_id))
        bindings = {'contract_id': contract_id}
        log.message(self.db, self.number, 'delete', 'contracts', bindings)
        cursor.execute('''DELETE FROM contracts WHERE contract_id = :contract_id''', bindings)
        log.message(self.db, self.number, 'delete', 'storage', bindings)
        cursor.execute('''DELETE FROM storage WHERE contract_id = :contract_id''', bindings)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
