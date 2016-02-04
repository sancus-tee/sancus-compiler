#ifndef SANCUS_SUPPORT_REACTIVE_H
#define SANCUS_SUPPORT_REACTIVE_H

#include "sm_support.h"

#include <stdint.h>

typedef uint16_t io_index;

#define __EXP(x) x

// The ASM symbols are used for the linker to be able to detect inputs/outputs

#define SM_OUTPUT(sm, name)                                             \
    asm("__sm_" __STR(sm) "_output_tag_" __STR(name) " = 0\n");         \
    SM_FUNC(sm) void __EXP(name)(const void* data, size_t len)          \
    {                                                                   \
        extern char __sm_##__EXP(sm)##_io_##__EXP(name)##_idx;          \
        SM_FUNC(sm) void __sm_##__EXP(sm)##_send_output(                \
                                   unsigned int, const void*, size_t);  \
        __sm_##__EXP(sm)##_send_output(                                 \
                (io_index)&__sm_##__EXP(sm)##_io_##__EXP(name)##_idx,   \
                data, len);                                             \
    }

#define SM_INPUT(sm, name, data_name, len_name)                         \
    asm("__sm_" __STR(sm) "_input_tag_" __STR(name) " = 0\n");          \
    SM_FUNC(sm) void name(const uint8_t* data_name, size_t len_name)

#endif
