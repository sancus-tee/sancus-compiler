#!/usr/bin/env python

from common import *

parser = argparse.ArgumentParser(description='SPM compiler for the MSP430.',
                                 parents=[get_common_parser()])
parser.add_argument('--spm-id',
                    help='ID for the SPM',
                    metavar='id')
parser.add_argument('--spm-stack-size',
                    help='Stack size for the SPM (in bytes)',
                    type=positive_int,
                    default=256,
                    metavar='size')
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

init_bc = get_tmp()
cc_args += ['-target', 'msp430-elf', '-c', '-emit-llvm', '-o', init_bc,
            args.in_files[0]]
call_prog('clang', cc_args)

if args.spm_id:
  opt_bc = get_tmp()
  opt_args = ['--load', 'SpmCreator.so', '--create-spm',
              '--spm-id', args.spm_id,
              '--spm-stack-size', str(args.spm_stack_size),
              '-o', opt_bc, init_bc]
  call_prog('opt', opt_args)
else:
  opt_bc = init_bc

assembly = get_tmp()
llc_args = ['-o', assembly, opt_bc]
call_prog('llc', llc_args)

as_args = ['-o', out_file, assembly]
call_prog('msp430-as', as_args)
