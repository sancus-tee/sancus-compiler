#!/usr/bin/env python

import re
import string

from elftools.elf.elffile import ELFFile

from common import *

def rename_syms_sects(file, sym_map, sect_map):
  args = []
  for old, new in sym_map.iteritems():
    args += ['--redefine-sym', '{}={}'.format(old, new)]
  for old, new in sect_map.iteritems():
    args += ['--rename-section', '{}={}'.format(old, new)]

  out_file = get_tmp()
  args += [file, out_file]
  call_prog('msp430-objcopy', args)
  return out_file

def parse_size(val):
  try:
    return int(val)
  except ValueError:
    match = re.match(r'(\d+)K', val)
    if not match:
      raise ValueError('Not a valid size expression: ' + val)
    return int(match.group(1)) * 1024

parser = argparse.ArgumentParser(description='SPM linker for the MSP430.',
                                 parents=[get_common_parser()])
parser.add_argument('--ram-size',
                    choices=['128', '256', '512', '1K', '2K', '4K', '5K',
                             '8K', '10K', '16K', '24K', '32K'],
                    default='128')
parser.add_argument('--rom-size',
                    choices=['1K', '2K', '4K', '8K', '12K', '16K', '24K',
                             '32K', '41K', '48K', '51K', '54K', '55K'],
                    default='2K')
parser.add_argument('-rdynamic', action='store_true')

args, ld_args = parser.parse_known_args()
set_args(args)

# find all defined SPMs
spms = set()
spms_table_order = {}
spms_entries = {}

for file_name in args.in_files:
  try:
    with open(file_name, 'rb') as file:
      elf_file = ELFFile(file)
      for section in elf_file.iter_sections():
        match = re.match(r'.spm.(\w+).', section.name)
        if match:
          spms.add(match.group(1))
          continue

        match = re.match(r'.rela.spm.(\w+).table', section.name)
        if match:
          spm_name = match.group(1)
          if not spm_name in spms_table_order:
            spms_table_order[spm_name] = []
            spms_entries[spm_name] = []

          spms_table_order[spm_name].append(file_name)

          #find entry points of the SPM in this file
          symtab = elf_file.get_section(section['sh_link'])
          entries = [(rel['r_offset'], symtab.get_symbol(rel['r_info_sym']).name)
                      for rel in section.iter_relocations()]
          entries.sort()
          spms_entries[spm_name] += [entry for _, entry in entries]
          print spm_name, spms_entries[spm_name]
  except IOError as e:
    fatal_error(str(e))

if len(spms) > 0:
  info('Found SPMs: ' + ', '.join(spms))
else:
  info('No SPMs found')

# create output sections for the the SPM to be inserted in the linker script
text_section = '''.text.spm.{0} :
  {{
    . = ALIGN(2);
    __spm_{0}_public_start = .;
    {1}
    {2}
    *(.spm.{0}.text)
    . = ALIGN(2);
    __spm_{0}_table = .;
    {3}
    . = ALIGN(2);
    __spm_{0}_public_end = .;
  }} > REGION_TEXT'''

data_section = '''.data.spm.{0} :
  {{
    . = ALIGN(2);
    __spm_{0}_secret_start = .;
    *(.spm.{0}.data)
    . = ALIGN(2);
    __spm_{0}_secret_end = .;
  }} > REGION_DATA'''

text_sections = []
data_sections = []
symbols = []
for spm in spms:
  tables = []
  for file in spms_table_order[spm]:
    tables.append('{}(.spm.{}.table)'.format(file, spm))

  nentries = '__spm_{}_nentries'.format(spm)
  sym_map = {'__spm_entry'    : '__spm_{}_entry'.format(spm),
             '__spm_nentries' : nentries,
             '__spm_table'    : '__spm_{}_table'.format(spm),
             '__spm_sp'       : '__spm_{}_sp'.format(spm),
             '__ret_entry'    : '__spm_{}_ret_entry'.format(spm),
             '__spm_exit'     : '__spm_{}_exit'.format(spm)}
  sect_map = {'.spm.text' : '.spm.{}.text'.format(spm)}
  
  entry_file = rename_syms_sects(get_data_path() + '/entry.o', sym_map, sect_map)
  exit_file = rename_syms_sects(get_data_path() + '/exit.o', sym_map, sect_map)
  args.in_files += [entry_file, exit_file]

  text_sections.append(text_section.format(spm, entry_file, exit_file,
                                           '\n    '.join(tables)))
  data_sections.append(data_section.format(spm))

  symbols.append('{} = {};'.format(nentries, len(spms_entries[spm])))
  for idx, entry in enumerate(spms_entries[spm]):
    sym_name = '__spm_{}_entry_{}_idx'.format(spm, entry)
    symbols.append('{} = {};'.format(sym_name, idx))

text_sections = '\n  '.join(text_sections)
data_sections = '\n  '.join(data_sections)
symbols = '\n'.join(symbols)

tmp_ldscripts_path = get_tmp_dir()
template_path = get_data_path()

if args.mcu:
  msp_paths = get_msp_paths()
  ldscripts_path = msp_paths['ldscripts']
  mcu_ldscripts_path = ldscripts_path + '/' + args.mcu

  if os.path.exists(mcu_ldscripts_path):
    info('Using linker scripts path: ' + mcu_ldscripts_path)
  else:
    fatal_error('No linker scripts found for MCU ' + args.mcu)
else:
  mcu_ldscripts_path = tmp_ldscripts_path
  shutil.copy(template_path + '/periph.x', mcu_ldscripts_path)

  ram_length = parse_size(args.ram_size)
  rom_length = parse_size(args.rom_size)
  rom_origin = 0x10000 - rom_length
  with open(template_path + '/memory.x', 'r') as memscript:
    template = string.Template(memscript.read())

  contents = template.substitute(ram_length=ram_length,
                                 rom_length=rom_length,
                                 rom_origin=rom_origin)
  with open(mcu_ldscripts_path + '/memory.x', 'w') as memscript:
    memscript.write(contents)

with open(template_path + '/msp430.x', 'r') as ldscript:
  template = string.Template(ldscript.read())

contents = template.substitute(spm_text_sections=text_sections,
                               spm_data_sections=data_sections,
                               spm_symbols=symbols)

ldscript_name = tmp_ldscripts_path + '/msp430.x'
with open(ldscript_name, 'w') as ldscript:
  ldscript.write(contents)

with open(ldscript_name, 'r') as ldscript:
  print ldscript.read()

out_file = args.out_file
if not out_file:
  out_file = 'a.out'

info('Using output file ' + out_file)

ld_args += ['-L', mcu_ldscripts_path, '-T', ldscript_name, '-o', out_file]
ld_args += args.in_files + ['-lspm-support']
call_prog('msp430-gcc', ld_args)
