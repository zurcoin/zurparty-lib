#! /usr/bin/python3

"""Execute arbitrary data as a smart contract."""

import struct
import binascii
import logging
logger = logging.getLogger(__name__)

from counterpartylib.lib import util
from counterpartylib.lib import config
from counterpartylib.lib import exceptions
from counterpartylib.lib import script

from . import pyeth

FORMAT = '>20sQQQ'
LENGTH = 44
ID = 101

def initialise (db):
    cursor = db.cursor()

    # Executions
    cursor.execute('''CREATE TABLE IF NOT EXISTS executions(
                      tx_index INTEGER UNIQUE,
                      tx_hash TEXT UNIQUE,
                      block_index INTEGER,
                      source TEXT,
                      contract_id TEXT,
                      gas_price INTEGER,
                      gas_start INTEGER,
                      gas_cost INTEGER,
                      gas_remained INTEGER,
                      value INTEGER,
                      data BLOB,
                      output BLOB,
                      status TEXT,
                      FOREIGN KEY (tx_index, tx_hash, block_index) REFERENCES transactions(tx_index, tx_hash, block_index))
                  ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      source_idx ON executions(source)
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      tx_hash_idx ON executions(tx_hash)
                   ''')

    # Contract Storage
    cursor.execute('''CREATE TABLE IF NOT EXISTS storage(
                      contract_id TEXT,
                      key BLOB,
                      value BLOB,
                      FOREIGN KEY (contract_id) REFERENCES contracts(contract_id))
                  ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      contract_id_idx ON contracts(contract_id)
                   ''')

    # Suicides
    cursor.execute('''CREATE TABLE IF NOT EXISTS suicides(
                      contract_id TEXT PRIMARY KEY,
                      FOREIGN KEY (contract_id) REFERENCES contracts(contract_id))
                  ''')

    # Nonces
    cursor.execute('''CREATE TABLE IF NOT EXISTS nonces(
                      address TEXT PRIMARY KEY,
                      nonce INTEGER)
                  ''')

    # Postqueue
    cursor.execute('''CREATE TABLE IF NOT EXISTS postqueue(
                      message BLOB)
                  ''')


def compose (db, source, contract_id, gasprice, startgas, value, payload_hex):
    if not config.TESTNET:  # TODO
        return

    payload = binascii.unhexlify(payload_hex)

    if startgas < 0:
        raise processblock.ContractError('negative startgas')
    if gasprice < 0:
        raise processblock.ContractError('negative gasprice')

    # Pack.
    data = struct.pack(config.TXTYPE_FORMAT, ID)
    curr_format = FORMAT + '{}s'.format(len(payload))
    data += struct.pack(curr_format, binascii.unhexlify(contract_id), gasprice, startgas, value, payload)

    return (source, [], data)

def unpack(db, message):
    try:
        format_ = FORMAT + '{}s'.format(len(message) - LENGTH)
        contract_id, gasprice, startgas, value, payload = struct.unpack(format_, message)

        # TODO: Define max for gasprice and startgas.
        if gasprice > config.MAX_INT or startgas > config.MAX_INT:
            raise exceptions.UnpackError()

        # TODO
        gas_remained = startgas

        # TODO
        contract_id = util.hexlify(contract_id)
        if contract_id == '0000000000000000000000000000000000000000':
            contract_id = ''

    except struct.error:
        raise UnpackError('could not unpack')

    except util.AssetNameError:
        raise UnpackError('asset id invalid')

    return contract_id, gasprice, startgas, value, payload


def parse (db, tx, message, pyeth_block):
    if not config.TESTNET:  # TODO
        return

    status = 'valid'
    output, gas_cost, gas_remained = None, None, None

    try:
        contract_id, gasprice, startgas, value, payload = unpack(db, message)

        import pyethereum.exceptions
        import pyethereum.transactions
        import pyethereum.processblock
        from counterpartylib.lib import script
   
        sender = script.base58_check_decode(tx['source'], config.ADDRESSVERSION) # TODO
        tx_obj = pyethereum.transactions.Transaction(pyeth_block.get_nonce(sender), gasprice, startgas, contract_id, value, payload)
        tx_obj.sender = sender

        success, output = pyethereum.processblock.apply_transaction(pyeth_block, tx_obj)
        print('SUCCESS {}'.format(success))
        print('OUTPUT {}'.format(output))

    except exceptions.UnpackError as e:
        contract_id, gasprice, startgas, value, payload = None, None, None, None, None
        status = 'invalid: could not unpack'
        output = None
    # except processblock.ContractError as e:
    #     status = 'invalid: no such contract'
    #     contract_id = None
    #     output = None
    # except processblock.OutOfGas as e:
    #     logger.debug('TX OUT_OF_GAS (startgas: {}, gas_remained: {})'.format(startgas, gas_remained))
    #     status = 'out of gas'
    #     output = None
    except pyethereum.exceptions.InsufficientStartGas as e:
        logger.debug(e)
        # logger.debug('Insufficient start gas: have {} and need {}'.format(have, need))
        status = 'invalid: insufficient start gas'
        output = None
    except pyethereum.exceptions.InsufficientBalance as e:
        logger.debug(e)
        # logger.debug('Insufficient balance: have {} and need {}'.format(actual, target))
        status = 'invalid: insufficient balance'
        output = None

    finally:

        if status == 'valid':
            logger.debug('TX FINISHED (gas_remained: {})'.format(gas_remained))

        # Add parsed transaction to message-type–specific table.
        bindings = {
            'tx_index': tx['tx_index'],
            'tx_hash': tx['tx_hash'],
            'block_index': tx['block_index'],
            'source': tx['source'],
            'contract_id': contract_id,
            'gasprice': gasprice,
            'startgas': startgas,
            'gas_cost': gas_cost,
            'gas_remained': gas_remained,
            'value': value,
            'payload': payload,
            'output': output,
            'status': status
        }
        sql='insert into executions values(:tx_index, :tx_hash, :block_index, :source, :contract_id, :gasprice, :startgas, :gas_cost, :gas_remained, :value, :data, :output, :status)'
        cursor = db.cursor()
        cursor.execute(sql, bindings)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
