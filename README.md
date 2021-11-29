# sancus-compiler
[![Sancus examples](https://github.com/sancus-tee/sancus-examples/actions/workflows/run-examples.yml/badge.svg)](https://github.com/sancus-tee/sancus-examples/actions/workflows/run-examples.yml)

Secure compilation of annotated C code to Sancus enclaves.

## Instalation

See [sancus-main](https://github.com/sancus-tee/sancus-main) for detailed installation instructions and reproducible builds.

## License

* The Sancus compiler toolchain is licensed under GPLv3, with an explicit [GCC runtime exception](https://www.gnu.org/licenses/gcc-exception-3.1.en.html) that allows proprietary code to be compiled with the Sancus toolchain.
* All code under `src/crypto/` implementing spongent/spongewrap cryptographic primitives and wrappers is placed in the public domain.
