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
parser.add_argument('-O',
                    dest='optimization',
                    help='Set optimization level',
                    choices=['0', '1', '2', '3'],
                    default='0')

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
gcc_include = msp_paths['gcc_include']
libc_include = msp_paths['libc_include']
cc_args += ['-I' + gcc_include, '-I' + libc_include]
info('Using include paths: {}, {}'.format(gcc_include, libc_include))

if args.mcu:
    mcu_define = '__' + args.mcu.upper() + '__'
else:
    mcu_define = '__MSP430F149__'

cc_args += ['-D' + mcu_define]
info('Using MCU define ' + mcu_define)

optimization = '-O' + args.optimization
cc_args.append(optimization)

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
    llc_args = [optimization, '-msp430-hwmult-mode=no', '-o', assembly, opt_bc]
    call_prog('llc', llc_args)

as_args += ['-c', '-o', out_file, assembly]
call_prog('msp430-gcc', as_args)
