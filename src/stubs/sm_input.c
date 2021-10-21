#include "reactive_stubs_support.h"

#include <alloca.h>
#include <stdlib.h>

uint16_t SM_ENTRY(SM_NAME) __sm_handle_input(uint16_t conn_idx,
                                         const void* payload, size_t len)
{
    // sanitize input buffer
    if(!sancus_is_outside_sm(SM_NAME, (void *) payload, len)) {
      return BufferInsideSM;
    }

    // check correctness of other parameters
    if(len < SANCUS_TAG_SIZE || conn_idx >= __sm_num_connections) {
      return IllegalParameters;
    }

    Connection *conn = &__sm_io_connections[conn_idx];

    // check if io_id is a valid input ID
    if (conn->io_id >= SM_NUM_INPUTS) {
      return IllegalConnection;
    }

    // associated data only contains the nonce, therefore we can use this
    // this trick to build the array fastly (i.e. by swapping the bytes)
    const uint16_t nonce_rev = conn->nonce << 8 | conn->nonce >> 8;
    const size_t data_len = len - SANCUS_TAG_SIZE;
    const uint8_t* cipher = payload;
    const uint8_t* tag = cipher + data_len;
    // TODO check for stack overflow!
    uint8_t* input_buffer = alloca(data_len);

    if (sancus_unwrap_with_key(conn->key, &nonce_rev, sizeof(nonce_rev),
                               cipher, data_len, tag, input_buffer)) {
       conn->nonce++;
       __sm_input_callbacks[conn->io_id](input_buffer, data_len);
       return Ok;
    }

    // here only if decryption fails
    return CryptoError;
}
