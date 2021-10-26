#ifndef SANCUS_SUPPORT_REACTIVE_H
#define SANCUS_SUPPORT_REACTIVE_H

#include "sm_support.h"

#include <stdint.h>

typedef uint16_t io_index;
typedef uint16_t conn_index;
typedef uint8_t  io_data __attribute__((aligned(2)));

// The ASM symbols are used for the linker to be able to detect inputs/outputs

#define SM_OUTPUT_AUX(sm, name)                                                \
    asm("__sm_" #sm "_output_tag_" #name " = 0\n");                            \
    SM_FUNC(sm) uint16_t name(const io_data* data, size_t len)                 \
    {                                                                          \
        extern char __sm_##sm##_io_##name##_idx;                               \
        SM_FUNC(sm) uint16_t __sm_##sm##_send_output(unsigned int,             \
                                                 const void*, size_t);         \
        return __sm_##sm##_send_output((io_index)&__sm_##sm##_io_##name##_idx, \
                                data, len);                                    \
    }

#define SM_OUTPUT(sm, name) SM_OUTPUT_AUX(sm, name)

#define SM_INPUT_AUX(sm, name, data_name, len_name)                     \
    asm("__sm_" #sm "_input_tag_" #name " = 0\n");                      \
    SM_FUNC(sm) void name(const uint8_t* data_name, size_t len_name)

#define SM_INPUT(sm, name, data_name, len_name)                         \
    SM_INPUT_AUX(sm, name, data_name, len_name)

#endif
