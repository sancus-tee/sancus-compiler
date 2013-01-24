#!/usr/bin/env python

import re
import string

from elftools.elf.elffile import ELFFile

from common import *

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

args = parser.parse_args()
set_args(args)

# find all defined SPMs
spms = set()

for file_name in args.in_files:
  try:
    with open(file_name, 'rb') as file:
      elf_file = ELFFile(file)
      for section in elf_file.iter_sections():
        match = re.match(r'.spm.(\w+).', section.name)
        if match:
          spms.add(match.group(1))
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
    *(.spm.{0}.text.entry)
    *(.spm.{0}.text)
    . = ALIGN(2);
  }} > REGION_TEXT
'''

data_section = '''.data.spm.{0} :
  {{
    . = ALIGN(2);
    *(.spm.{0}.data)
    . = ALIGN(2);
  }} > REGION_DATA
'''

text_sections = ''
data_sections = ''
for spm in spms:
  text_sections += text_section.format(spm)
  data_sections += data_section.format(spm)

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
                               spm_data_sections=data_sections)

ldscript_name = tmp_ldscripts_path + '/msp430.x'
with open(ldscript_name, 'w') as ldscript:
  ldscript.write(contents)

#with open(ldscript_name, 'r') as ldscript:
  #print ldscript.read()

out_file = args.out_file
if not out_file:
  out_file = 'a.out'

info('Using output file ' + out_file)

ld_args = ['-L', mcu_ldscripts_path, '-T', ldscript_name, '-o', out_file]
ld_args += args.in_files
call_prog('msp430-gcc', ld_args)
