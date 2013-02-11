#!/usr/bin/env python

from common import *

import ctypes
import struct
import re

from elftools.elf.elffile import ELFFile

_lib = ctypes.cdll.LoadLibrary(get_data_path() + '/libhmac-spongent.so')

def _gen_lib_call(func):
  def lib_call(key, msg, hex_out=True):
    ret = '\x00' * 16
    func(key, msg, len(msg), ret)
    return ret.encode('hex') if hex_out else ret
  return lib_call

hmac = _gen_lib_call(_lib.hmac)
hkdf = _gen_lib_call(_lib.hkdf)

def _get_spm_section(elf_file, spm):
  spm_section = elf_file.get_section_by_name('.text.spm.' + spm)
  if not spm_section:
    raise ValueError('No such SPM: ' + spm)
  return spm_section

def _get_symbols(elf_file):
  from elftools.elf.sections import SymbolTableSection
  return {symbol.name : symbol['st_value']
            for section in elf_file.iter_sections()
              if isinstance(section, SymbolTableSection)
                for symbol in section.iter_symbols()}

def _int_to_bytes(i):
  assert 0 <= i < 2 ** 16
  return struct.pack('>H', i)

def _parse_hex(hex_str, size = 0):
  if size > 0 and len(hex_str) != size:
    raise argparse.ArgumentTypeError('Incorrect hex size')
  try:
    return hex_str.decode('hex')
  except TypeError:
    raise argparse.ArgumentTypeError('Incorrect hex format')

def _parse_key(key_str):
  return _parse_hex(key_str, 32)

def _parse_id(id_str):
  return _parse_hex(id_str, 4)

def get_spm_key(file, spm, master_key, hex_out=True):
  elf_file = ELFFile(file)
  return hkdf(master_key, _get_spm_section(elf_file, spm).data(), hex_out)

def get_spm_hmac(file, spm, key, hex_out=True):
  elf_file = ELFFile(file)
  data = _get_spm_section(elf_file, spm).data()
  symbols = _get_symbols(elf_file)
  prefix = '__spm_{}_'.format(spm)
  names = [prefix + s for s in ['public_start', 'public_end',
                                'secret_start', 'secret_end']]
  for name in names:
    try:
      data += _int_to_bytes(symbols[name])
    except KeyError:
      fatal_error('Symbol {} not found'.format(name))

  return hmac(key, data, hex_out)

def fill_hmac_sections(file):
  elf_file = ELFFile(file)
  keys = {}
  shutil.copy(args.in_file, args.out_file)

  with open(args.out_file, 'r+') as out_file:
    for section in elf_file.iter_sections():
      match = re.match(r'.data.spm.(\w+).hmac.(\w+)', section.name)
      if match:
        caller = match.group(1)
        callee = match.group(2)
        if not caller in keys:
          keys[caller] = get_spm_key(file, caller, args.key, False)
          info('Key used for SPM {}: {}'.format(caller, keys[caller].encode('hex')))

        hmac = get_spm_hmac(file, callee, keys[caller], False)
        info('HMAC of {} used by {}: {}'.format(callee, caller, hmac.encode('hex')))
        out_file.seek(section['sh_offset'])
        out_file.write(hmac)

# FIXME this should be moved to the common argument parser!
parser = argparse.ArgumentParser()
parser.add_argument('--verbose',
                    help='Show information messages',
                    action='store_true')
parser.add_argument('--debug',
                    help='Show debug output and keep intermediate files',
                    action='store_true')
parser.add_argument('--hmac',
                    help='Generate HMAC for SPM',
                    metavar='SPM')
parser.add_argument('--hkdf',
                    help='Generate derived key for SPM',
                    metavar='SPM')
parser.add_argument('--key',
                    help='128-bit key in hexadecimal format',
                    type=_parse_key,
                    metavar='key',
                    required=True)
parser.add_argument('--vendor-key',
                    help='Generate the vendor key for the given ID',
                    type=_parse_id,
                    metavar='ID')
parser.add_argument('--signature',
                    help='Generate a signature of the given data',
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
  if args.vendor_key:
    print hkdf(args.key, args.vendor_key)
  elif args.signature:
    print hmac(args.key, args.signature)
  else:
    with open(args.in_file, 'r') as file:
      if args.hkdf:
        print(get_spm_key(file, args.hkdf, args.key))
      elif args.hmac:
        print(get_spm_hmac(file, args.hmac, args.key))
      else:
        if not args.out_file:
          fatal_error('Requested to fill HMAC sections but no output file given')
        else:
          fill_hmac_sections(file)
except IOError as e:
  fatal_error('Cannot open file: ' + str(e))
#except Exception as e:
  #fatal_error(str(e))
