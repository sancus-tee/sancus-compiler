#include "reactive_stubs_support.h"

#include <alloca.h>

#define AD_SIZE 2

void SM_ENTRY(SM_NAME) __sm_handle_input(uint16_t conn_id,
                                         const void* payload, size_t len)
{
    if (conn_id >= SM_NUM_INPUTS)
        return;

    const size_t data_len = len - AD_SIZE - SANCUS_TAG_SIZE;
    const uint8_t* cipher = (uint8_t*)payload + AD_SIZE;
    const uint8_t* tag = cipher + data_len;

    // TODO check for stack overflow!
    uint8_t* input_buffer = alloca(data_len);

    if (sancus_unwrap_with_key(__sm_io_keys[conn_id], payload, AD_SIZE,
                               cipher, data_len, tag, input_buffer))
    {
        __sm_input_callbacks[conn_id](input_buffer, data_len);
    }
}
