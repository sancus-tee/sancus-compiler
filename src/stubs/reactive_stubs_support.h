#ifndef REACTIVE_PRIVATE_H
#define REACTIVE_PRIVATE_H

#include "reactive.h"

void reactive_handle_output(conn_index conn_id, void* data, size_t len);

typedef uint8_t IoKey[SANCUS_KEY_SIZE];
typedef void (*InputCallback)(const void*, size_t);

typedef enum
{
    Ok                    = 0x0,
    IllegalConnection     = 0x1,
    MalformedPayload      = 0x2,
    IllegalParameters     = 0x3,
    BufferInsideSM        = 0x4,
    CryptoError           = 0x5,
    InternalError         = 0x6
} ResultCode;

typedef struct Connection {
    io_index    io_id;
    conn_index  conn_id;
    uint16_t    nonce;
    IoKey       key;
} Connection;

// The size of the Connection struct is also hardcoded in linker.py. Hence,
// we need to make sure that it does not change at compile time (e.g. due to
// optimizations).
// Besides, if the struct changes, we need to adjust this value here and in
// linker.py (check the CONNECTION_STRUCT_SIZE global variable) as well.
_Static_assert (sizeof(Connection) == 6 + SANCUS_KEY_SIZE,
    "Size of Connection struct differs from the expected value");

// These will be allocated by the linker
extern Connection __sm_io_connections[];
extern InputCallback __sm_input_callbacks[];

extern char __sm_max_connections;
#define SM_MAX_CONNECTIONS (size_t)&__sm_max_connections

extern uint16_t __sm_num_connections;

extern char __sm_num_inputs;
#define SM_NUM_INPUTS (size_t)&__sm_num_inputs

#define SM_NAME X

// declare symbols for the public/secret regions
#define __SECTION(sect, name) sect(name)
extern char __SECTION(__PS, SM_NAME), __SECTION(__PE, SM_NAME),
            __SECTION(__SS, SM_NAME), __SECTION(__SE, SM_NAME);

#endif
