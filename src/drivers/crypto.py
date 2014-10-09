#!/usr/bin/env python3

import config
from common import *

import ctypes
import struct
import re
import binascii

from elftools.elf.elffile import ELFFile

KEY_SIZE = config.SECURITY

_lib = ctypes.cdll.LoadLibrary(get_data_path() + '/libsancus-crypto.so')


def _parse_hex(hex_str, size=0):
    if size > 0 and len(hex_str) != size:
        raise argparse.ArgumentTypeError('Incorrect hex size')
    try:
        return bytes.fromhex(hex_str)
    except TypeError:
        raise argparse.ArgumentTypeError('Incorrect hex format')


def _get_hex_str(b):
    return binascii.hexlify(b).decode('ascii')

def _print_data(data):
    for i, b in enumerate(data):
        need_nl = True
        print(b.encode('hex'), end='')
        if (i + 1) % 26 == 0:
            need_nl = False
            print()
    if need_nl:
        print()


def _output_data(data):
    if sys.stdout.isatty():
        print(_get_hex_str(data))
    else:
        sys.stdout.buffer.write(data)


def wrap(key, ad, body):
    cipher = bytes(len(body))
    tag = bytes(int(KEY_SIZE / 8))
    ok = _lib.sancus_wrap(key, ad, ctypes.c_ulonglong(len(ad)),
                          body, ctypes.c_ulonglong(len(body)), cipher, tag)
    return (cipher, tag) if ok else None


def unwrap(key, ad, cipher, tag):
    body = bytes(len(cipher))
    ok = _lib.sancus_unwrap(key, ad, ctypes.c_ulonglong(len(ad)),
                            cipher, ctypes.c_ulonglong(len(cipher)), tag, body)
    return body if ok else None


def mac(key, msg):
    ret = bytes(int(KEY_SIZE / 8))
    _lib.sancus_mac(key, msg, ctypes.c_ulonglong(len(msg)), ret)
    return ret


def _get_sm_section(elf_file, sm):
    sm_section = elf_file.get_section_by_name(bytes('.text.sm.' + sm, 'ascii'))
    if sm_section is None:
        raise ValueError('No such SM: ' + sm)
    return sm_section


def _get_symbols(elf_file):
    from elftools.elf.sections import SymbolTableSection
    return {symbol.name.decode('ascii'): symbol['st_value']
                for section in elf_file.iter_sections()
                    if isinstance(section, SymbolTableSection)
                        for symbol in section.iter_symbols()}


def _int_to_bytes(i):
    assert 0 <= i < 2 ** 16
    return struct.pack('<H', i)


def _parse_key(key_str):
    return _parse_hex(key_str, KEY_SIZE / 4)


def _parse_id(id_str):
    # id is an integer so should be LE -> reverse the parsed byte array
    return _parse_hex(id_str, 4)[::-1]


def _get_sm_identity(file, sm):
    elf_file = ELFFile(file)
    identity = _get_sm_section(elf_file, sm).data()
    symbols = _get_symbols(elf_file)
    prefix = '__sm_{}_'.format(sm)
    names = [prefix + s for s in ['public_start', 'public_end',
                                  'secret_start', 'secret_end']]
    for name in names:
        try:
            identity += _int_to_bytes(symbols[name])
        except KeyError:
            fatal_error('Symbol {} not found'.format(name))
    return identity

def get_sm_key(file, sm, master_key):
    return mac(master_key, _get_sm_identity(file, sm))


def get_sm_mac(file, sm, key):
    return mac(key, _get_sm_identity(file, sm))


def fill_mac_sections(file):
    elf_file = ELFFile(file)
    keys = {}
    shutil.copy(args.in_file, args.out_file)

    with open(args.out_file, 'rb+') as out_file:
        for section in elf_file.iter_sections():
            name = section.name.decode('ascii')
            match = re.match(r'.data.sm.(\w+).mac.(\w+)', name)
            if match:
                caller = match.group(1)
                callee = match.group(2)
                if not caller in keys:
                    keys[caller] = get_sm_key(file, caller, args.key)
                    hex_key = _get_hex_str(keys[caller])
                    info('Key used for SM {}: {}'.format(caller, hex_key))

                try:
                    mac = get_sm_mac(file, callee, keys[caller])
                    msg = 'MAC of {} used by {}: {}'
                    info(msg.format(callee, caller, _get_hex_str(mac)))
                    out_file.seek(section['sh_offset'])
                    out_file.write(mac)
                except ValueError:
                    # FIXME: this is a compiler bug workaround
                    warning('Not adding MAC for call to unknown SM {}'
                                .format(callee))

# FIXME this should be moved to the common argument parser!
parser = argparse.ArgumentParser()
parser.add_argument('--verbose',
                    help='Show information messages',
                    action='store_true')
parser.add_argument('--debug',
                    help='Show debug output and keep intermediate files',
                    action='store_true')
parser.add_argument('--mac',
                    help='Generate MAC for SM',
                    metavar='SM')
parser.add_argument('--gen-sm-key',
                    help='Generate derived key for SM',
                    metavar='SM')
parser.add_argument('--key',
                    help='{}-bit key in hexadecimal format'.format(KEY_SIZE),
                    type=_parse_key,
                    metavar='key',
                    required=True)
parser.add_argument('--gen-vendor-key',
                    help='Generate the vendor key for the given ID',
                    type=_parse_id,
                    metavar='ID')
parser.add_argument('--wrap',
                    help='Wrap the given associated data/body pair',
                    type=_parse_hex,
                    nargs=2,
                    metavar=('AD', 'BODY'))
parser.add_argument('--unwrap',
                    help='Wrap the given associated data/cipher/tag triplet',
                    type=_parse_hex,
                    nargs=3,
                    metavar=('AD', 'CIPHER', 'TAG'))
parser.add_argument('--tag',
                    help='Generate a tag of the given data',
                    type=_parse_hex,
                    metavar='data')
parser.add_argument('-o',
                    help='Output file',
                    dest='out_file',
                    metavar='file')
parser.add_argument('in_file',
                    help='Input file',
                    metavar='file',
                    nargs='?')

args = parser.parse_args()
set_args(args)

try:
    if args.gen_vendor_key:
        _output_data(mac(args.key, args.gen_vendor_key))
    elif args.wrap:
        ad, body = args.wrap
        cipher, tag = wrap(args.key, ad, body)
        _output_data(tag)
        _output_data(cipher)
    elif args.unwrap:
        ad, cipher, tag = args.unwrap
        body = unwrap(args.key, ad, cipher, tag)

        if body:
            _output_data(body)
        else:
            fatal_error('Incorrect tag')
    elif args.mac:
        with open(args.in_file, 'rb') as file:
            _output_data(get_sm_mac(file, args.mac, args.key))
    elif args.tag:
        _output_data(mac(args.key, args.tag))
    else:
        with open(args.in_file, 'rb') as file:
            if args.gen_sm_key:
                _output_data(get_sm_key(file, args.gen_sm_key, args.key))
            else:
                if not args.out_file:
                    fatal_error('Requested to fill MAC sections but no ' +
                                'output file given')
                else:
                    fill_mac_sections(file)
except IOError as e:
    fatal_error('Cannot open file: ' + str(e))
except Exception as e:
    fatal_error(str(e))
