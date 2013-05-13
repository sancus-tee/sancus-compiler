#!/usr/bin/env python

from common import *


def is_assembly(file):
    _, ext = os.path.splitext(file)
    return ext.lower() == '.s'


parser = argparse.ArgumentParser(description='Sancus module compiler.',
                                 parents=[get_common_parser()])
parser.add_argument('-c',
                    dest='compile_only',
                    help='Compile and assemble, but do not link',
                    action='store_true')

args, cc_args = parser.parse_known_args()
set_args(args)

if len(args.in_files) != 1:
    fatal_error('Exactly 1 input file is required')
if not args.compile_only:
    fatal_error('-c has to be given')

in_file = args.in_files[0]

if not args.out_file:
    out_file = os.path.splitext(args.in_files[0])[0] + '.o'
else:
    out_file = args.out_file

info('Using output file ' + out_file)

msp_paths = get_msp_paths()
include_path = msp_paths['include']
cc_args += ['-I' + include_path]
info('Using include path: ' + include_path)

if args.mcu:
    mcu_define = '__' + args.mcu.upper() + '__'
else:
    mcu_define = '__MSP430F149__'

cc_args += ['-D' + mcu_define]
info('Using MCU define ' + mcu_define)

as_args = []

if is_assembly(in_file):
    assembly = in_file
    as_args = cc_args
else:
    init_bc = get_tmp('.bc')
    cc_args += ['-target', 'msp430-elf', '-c', '-emit-llvm',
                '-o', init_bc, in_file]
    call_prog('clang', cc_args)

    opt_bc = get_tmp('.bc')
    opt_args = ['--load', 'SancusModuleCreator.so', '--create-sm',
                '-o', opt_bc, init_bc]
    call_prog('opt', opt_args)

    assembly = get_tmp('.s')
    llc_args = ['-o', assembly, opt_bc]
    call_prog('llc', llc_args)

as_args += ['-c', '-o', out_file, assembly]
call_prog('msp430-gcc', as_args)
