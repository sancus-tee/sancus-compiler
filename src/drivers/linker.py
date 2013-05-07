#!/usr/bin/env python

import re
import string

from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

from common import *


def rename_syms_sects(file, sym_map, sect_map):
    args = []
    for old, new in sym_map.iteritems():
        args += ['--redefine-sym', '{}={}'.format(old, new)]
    for old, new in sect_map.iteritems():
        args += ['--rename-section', '{}={}'.format(old, new)]

    out_file = get_tmp('.o')
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


parser = argparse.ArgumentParser(description='Sancus module linker.',
                                 parents=[get_common_parser()])
parser.add_argument('--standalone', action='store_true')
parser.add_argument('--ram-size',
                    choices=['128', '256', '512', '1K', '2K', '4K', '5K',
                             '8K', '10K', '16K', '24K', '32K'],
                    default='10K')
parser.add_argument('--rom-size',
                    choices=['1K', '2K', '4K', '8K', '12K', '16K', '24K',
                             '32K', '41K', '48K', '51K', '54K', '55K'],
                    default='48K')
parser.add_argument('-rdynamic', action='store_true')
parser.add_argument('--spm-stack-size',
                    help='Stack size for the module (in bytes)',
                    type=positive_int,
                    default=256,
                    metavar='size')

args, ld_args = parser.parse_known_args()
set_args(args)

# find all defined SPMs
spms = set()
spms_table_order = {}
spms_entries = {}
spms_calls = {}

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
                    entries = [(rel['r_offset'],
                                symtab.get_symbol(rel['r_info_sym']).name)
                                    for rel in section.iter_relocations()]
                    entries.sort()
                    spms_entries[spm_name] += [entry for _, entry in entries]
                    continue

                match = re.match(r'.rela.spm.(\w+).text', section.name)
                if match:
                    spm_name = match.group(1)

                    #find call from this SPM to others
                    symtab = elf_file.get_section(section['sh_link'])
                    for rel in section.iter_relocations():
                        rel_match = re.match(r'__spm_(\w+)_entry',
                                             symtab.get_symbol(
                                                 rel['r_info_sym']).name)
                        if rel_match:
                            assert rel_match.group(1) != spm_name
                            if not spm_name in spms_calls:
                                spms_calls[spm_name] = set()
                            spms_calls[spm_name].add(rel_match.group(1))
                    continue
    except IOError as e:
        fatal_error(str(e))
    except ELFError as e:
        debug('Not checking {} for SPMs because it is not a valid '
              'ELF file ({})'.format(file_name, e))

if len(spms) > 0:
    info('Found Sancus modules:')
    for spm in spms:
        info(' * {}:'.format(spm))
        if spm in spms_entries:
            info('  - Entries: {}'.format(', '.join(spms_entries[spm])))
        else:
            info('  - No entries')
        if spm in spms_calls:
            info('  - Calls:   {}'.format(', '.join(spms_calls[spm])))
        else:
            info('  - No calls to other modules')
else:
    info('No Sancus modules found')

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
  }}'''

data_section = '''.data.spm.{0} :
  {{
    . = ALIGN(2);
    __spm_{0}_secret_start = .;
    *(.spm.{0}.data)
    {1}
    . += {2};
    __spm_{0}_stack_init = .;
    __spm_{0}_sp = .;
    . += 2;
    . = ALIGN(2);
    __spm_{0}_secret_end = .;
  }}'''

hmac_section = '''.data.spm.{0}.hmac.{1} :
  {{
    . = ALIGN(2);
    __spm_{0}_hmac_{1} = .;
    BYTE(0x00); /* without this, this section will be empty in the binary */
    . += 15;
  }}'''

if args.standalone:
    text_section += ' > REGION_TEXT'
    data_section += ' > REGION_DATA'
    hmac_section += ' > REGION_TEXT'

text_sections = []
data_sections = []
hmac_sections = []
symbols = []
for spm in spms:
    nentries = '__spm_{}_nentries'.format(spm)
    sym_map = {'__spm_entry'      : '__spm_{}_entry'.format(spm),
               '__spm_nentries'   : nentries,
               '__spm_table'      : '__spm_{}_table'.format(spm),
               '__spm_sp'         : '__spm_{}_sp'.format(spm),
               '__ret_entry'      : '__spm_{}_ret_entry'.format(spm),
               '__spm_exit'       : '__spm_{}_exit'.format(spm),
               '__spm_stack_init' : '__spm_{}_stack_init'.format(spm),
               '__spm_verify'     : '__spm_{}_verify'.format(spm)}
    sect_map = {'.spm.text' : '.spm.{}.text'.format(spm)}

    tables = []
    if spm in spms_table_order:
        tables = ['{}(.spm.{}.table)'.format(file, spm)
                      for file in spms_table_order[spm]]

    id_syms = []
    if spm in spms_calls:
        for callee in spms_calls[spm]:
            hmac_sections.append(hmac_section.format(spm, callee))
            id_syms += ['__spm_{}_id_{} = .;'.format(spm, callee), '. += 2;']

        verify_file = rename_syms_sects(get_data_path() + '/sm_verify.o',
                                        sym_map, sect_map)
        args.in_files.append(verify_file)

    entry_file = rename_syms_sects(get_data_path() + '/sm_entry.o',
                                   sym_map, sect_map)
    exit_file = rename_syms_sects(get_data_path() + '/sm_exit.o',
                                  sym_map, sect_map)
    args.in_files += [entry_file, exit_file]

    text_sections.append(text_section.format(spm, entry_file, exit_file,
                                             '\n    '.join(tables)))
    data_sections.append(data_section.format(spm, '\n    '.join(id_syms),
                                             args.spm_stack_size))

    symbols.append('{} = {};'.format(nentries, len(spms_entries[spm])))
    for idx, entry in enumerate(spms_entries[spm]):
        sym_name = '__spm_{}_entry_{}_idx'.format(spm, entry)
        symbols.append('{} = {};'.format(sym_name, idx))

text_sections = '\n  '.join(text_sections)
data_sections = '\n  '.join(data_sections)
hmac_sections = '\n  '.join(hmac_sections)
symbols = '\n'.join(symbols)

tmp_ldscripts_path = get_tmp_dir()
template_path = get_data_path()
msp_paths = get_msp_paths()

if args.standalone:
    if args.mcu:
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
else:
    mcu_ldscripts_path = tmp_ldscripts_path
    with open(template_path + '/sancus.ld', 'r') as ldscript:
        template = string.Template(ldscript.read())

contents = template.substitute(spm_text_sections=text_sections,
                               spm_data_sections=data_sections,
                               spm_hmac_sections=hmac_sections,
                               spm_symbols=symbols,
                               mcu_ldscripts_path=mcu_ldscripts_path)

ldscript_name = tmp_ldscripts_path + '/msp430.x'
with open(ldscript_name, 'w') as ldscript:
    ldscript.write(contents)

#with open(ldscript_name, 'r') as ldscript:
    #print ldscript.read()

out_file = args.out_file
if not out_file:
    out_file = 'a.out'

info('Using output file ' + out_file)

ld_args += ['-L', mcu_ldscripts_path, '-L', msp_paths['lib'],
            '-T', ldscript_name, '-o', out_file]
ld_libs = ['-lsancus-sm-support']

if args.standalone:
    ld_libs += ['-lsancus-host-support']
    ld_args += args.in_files + ld_libs
    call_prog('msp430-gcc', ld_args)
else:
    ld_args += ['-r'] + args.in_files + ld_libs
    call_prog('msp430-ld', ld_args)
