#ifndef REACTIVE_PRIVATE_H
#define REACTIVE_PRIVATE_H

#include "reactive.h"

void reactive_handle_output(io_index output_id, void* data, size_t len);

typedef uint8_t IoKey[SANCUS_KEY_SIZE];
typedef void (*InputCallback)(const void*, size_t);

typedef enum
{
    Ok                = 0x0,
    IllegalConnection = 0x1,
    MalformedPayload  = 0x2
} ResultCode;

// These will be allocated by the linker
extern IoKey __sm_io_keys[];
extern InputCallback __sm_input_callbacks[];
extern uint16_t __sm_output_nonce;

extern char __sm_num_connections;
#define SM_NUM_CONNECTIONS (size_t)&__sm_num_connections

extern char __sm_num_inputs;
#define SM_NUM_INPUTS (size_t)&__sm_num_inputs

#define SM_NAME X

#endif
