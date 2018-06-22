#!/usr/bin/env python3

from . import config
from . import paths

import ctypes
import struct
import re
import binascii
import logging
import argparse
import sys
import shutil

from elftools.elf.elffile import ELFFile

KEY_SIZE = config.SECURITY

_lib = ctypes.cdll.LoadLibrary(paths.get_data_path() + '/libsancus-crypto.so')

dump_c_array = 0

class Error(Exception):
    pass


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


def _output_data(data, dump_c_array=False):
    if sys.stdout.isatty():
        s = _get_hex_str(data)
        if dump_c_array:
            print('uint8_t key[] = {', end=' ');

            i = 0
            h = ''
            for c in s:
                if (i % 2) == 0:
                    h = c
                else:
                    print('0x' + h + c, end=', ')
                i = i + 1

            sys.stdout.write('\b \b\b')
            print('};')
        else:
            print(s)
    else:
        sys.stdout.buffer.write(data)


def _get_sm_wrap_nonce(name, body):
    return wrap(0, bytes(name, 'utf-8'), body)[1][:2][::-1]

def wrap(key, ad, body):
    # NOTE ctypes only understands bytes, not bytearrays
    cipher = bytes(len(body))
    tag = bytes(int(KEY_SIZE / 8))
    ok = _lib.sancus_wrap(bytes(key), bytes(ad), ctypes.c_ulonglong(len(ad)),
                          bytes(body), ctypes.c_ulonglong(len(body)),
                          cipher, tag)
    return (cipher, tag) if ok else None


def unwrap(key, ad, cipher, tag):
    body = bytes(len(cipher))
    ok = _lib.sancus_unwrap(bytes(key), bytes(ad), ctypes.c_ulonglong(len(ad)),
                            bytes(cipher), ctypes.c_ulonglong(len(cipher)),
                            bytes(tag), bytes(body))
    return body if ok else None


def mac(key, msg):
    ret = bytes(int(KEY_SIZE / 8))
    _lib.sancus_mac(bytes(key), bytes(msg), ctypes.c_ulonglong(len(msg)), ret)
    return ret


def _get_sm_section(elf_file, sm):
    sm_section = elf_file.get_section_by_name('.text.sm.{}'.format(sm))
    if sm_section is None:
        raise ValueError('No such SM: ' + sm)
    return sm_section


def _get_symbols(elf_file):
    from elftools.elf.sections import SymbolTableSection
    return {symbol.name: symbol['st_value']
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
        except KeyError as e:
            raise Error('Symbol {} not found'.format(name)) from e
    return identity

def get_sm_key(file, sm, master_key):
    return mac(master_key, _get_sm_identity(file, sm))


def get_sm_mac(file, sm, key):
    return mac(key, _get_sm_identity(file, sm))


def fill_mac_sections(file, output_path):
    elf_file = ELFFile(file)
    shutil.copy(file.name, output_path)

    with open(output_path, 'rb+') as out_file:
        for section in elf_file.iter_sections():
            name = section.name
            match = re.match(r'.data.sm.(\w+).mac.(\w+)', name)
            if match:
                caller = match.group(1)
                callee = match.group(2)
                key = bytes(KEY_SIZE // 8)

                try:
                    mac = get_sm_mac(file, callee, key)
                    msg = 'MAC of {} used by {}: {}'
                    logging.info(msg.format(callee, caller, _get_hex_str(mac)))
                    out_file.seek(section['sh_offset'])
                    out_file.write(mac)
                except ValueError:
                    # FIXME: this is a compiler bug workaround
                    msg = 'Not adding MAC for call to unknown SM {} ' \
                          '(FIXME: this is a compiler bug)'
                    logging.info(msg.format(callee))


def wrap_sm_text_sections(file, output_path, key):
    elf_file = ELFFile(file)
    shutil.copy(file.name, output_path)

    with open(output_path, 'rb+') as out_file:
        for section in elf_file.iter_sections():
            match = re.match(r'.text.sm.(\w+)', section.name)

            if not match:
                continue

            section_name, sm_name = match.group(0, 1)
            logging.info('Wrapping text section of SM %s', sm_name)
            section = elf_file.get_section_by_name(section_name)
            nonce = _get_sm_wrap_nonce(sm_name, section.data())
            wrapped_section_data, tag = wrap(key, nonce, section.data())

            # Write wrapped section to output file
            out_file.seek(section['sh_offset'])
            out_file.write(wrapped_section_data)

            # Write [nonce, tag] to the wrapinfo section.
            # FIXME use % formatting when bumping Python version to 3.5
            wrapinfo_name = '.data.sm.{}.wrapinfo'.format(sm_name)
            wrapinfo_section = elf_file.get_section_by_name(wrapinfo_name)

            if wrapinfo_section is None:
                raise Error('No wrapinfo section found. Did you links with '
                            '--prepare-for-sm-text-section-wrapping?')

            wrapinfo_data = nonce + tag
            out_file.seek(wrapinfo_section['sh_offset'])
            out_file.write(wrapinfo_data)


def main():
    parser = argparse.ArgumentParser()

    # FIXME this should really be cleaned up!
    parser.add_argument('--verbose',
                        help='Show information messages',
                        action='store_true')
    parser.add_argument('--debug',
                        help='Show debug output and keep intermediate files',
                        action='store_true')
    parser.add_argument('--c-array',
                        help='Print generated key in copy-paste C uint8_t array format',
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
                        metavar='key')
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
    parser.add_argument('--fill-macs',
                        help='Fill the MAC sections',
                        action='store_true')
    parser.add_argument('--wrap-sm-text-sections',
                        help='Wrap the text sections with the given key',
                        action='store_true')
    parser.add_argument('-o',
                        help='Output file',
                        dest='out_file',
                        metavar='file')
    parser.add_argument('in_file',
                        help='Input file',
                        metavar='file',
                        nargs='?')

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    if args.gen_vendor_key:
        _output_data(mac(args.key, args.gen_vendor_key), args.c_array)
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
            raise Error('Incorrect tag')
    elif args.mac:
        with open(args.in_file, 'rb') as file:
            _output_data(get_sm_mac(file, args.mac, args.key))
    elif args.tag:
        _output_data(mac(args.key, args.tag))
    else:
        with open(args.in_file, 'rb') as file:
            if args.gen_sm_key:
                _output_data(get_sm_key(file, args.gen_sm_key, args.key), args.c_array)
            else:
                if not args.out_file:
                    raise Error('Requested to fill MAC sections or wrap text '
                                'sections but no output file given')

                if args.fill_macs:
                    fill_mac_sections(file, args.out_file)
                elif args.wrap_sm_text_sections:
                    wrap_sm_text_sections(file, args.out_file, args.key)
                else:
                    raise Error('If an output file is given, either --fill-macs'
                                ' or --wrap-sm-text-sections should be given')


if __name__ == '__main__':
    try:
        main()
    except IOError as e:
        logging.error('Cannot open file: {}'.format(str(e)))
        sys.exit(1)
    except Exception as e:
        logging.error(str(e))
        sys.exit(1)
