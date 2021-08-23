#ifndef REACTIVE_PRIVATE_H
#define REACTIVE_PRIVATE_H

#include "reactive.h"

void reactive_handle_output(conn_index conn_id, void* data, size_t len);

typedef uint8_t IoKey[SANCUS_KEY_SIZE];
typedef void (*InputCallback)(const void*, size_t);

typedef enum
{
    Ok                = 0x0,
    IllegalConnection = 0x1,
    MalformedPayload  = 0x2,
    InternalError     = 0x3
} ResultCode;

typedef struct Connection {
    io_index    io_id;
    conn_index  conn_id;
    uint16_t    nonce;
    IoKey       key;
} Connection;

// These will be allocated by the linker
extern Connection __sm_io_connections[];
extern InputCallback __sm_input_callbacks[];

extern char __sm_max_connections;
#define SM_MAX_CONNECTIONS (size_t)&__sm_max_connections

extern uint16_t __sm_num_connections;

extern char __sm_num_inputs;
#define SM_NUM_INPUTS (size_t)&__sm_num_inputs

#define SM_NAME X

#endif
