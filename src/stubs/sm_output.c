#include "reactive_stubs_support.h"

#include <stdlib.h>

SM_FUNC(SM_NAME) void __sm_send_output(io_index index,
                                       const void* data, size_t len)
{
    const size_t nonce_len = sizeof(__sm_output_nonce);
    const size_t payload_len = nonce_len + len + SANCUS_TAG_SIZE;
    uint8_t* payload = malloc(payload_len);
    *(uint16_t*)payload = __sm_output_nonce++;
    sancus_wrap_with_key(__sm_io_keys[index], payload, nonce_len, data, len,
                         payload + nonce_len, payload + nonce_len + len);
    reactive_handle_output(index, payload, payload_len);
}
