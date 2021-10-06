#include "reactive_stubs_support.h"

#define AD_SIZE 6

uint16_t SM_ENTRY(SM_NAME) __sm_set_key(const uint8_t* ad, const uint8_t* cipher,
                                    const uint8_t* tag, uint16_t *conn_idx)
{
    if( !sancus_is_outside_sm(SM_NAME, (void *) ad, AD_SIZE) ||
        !sancus_is_outside_sm(SM_NAME, (void *) cipher, SANCUS_KEY_SIZE) ||
        !sancus_is_outside_sm(SM_NAME, (void *) tag, SANCUS_TAG_SIZE) ||
        !sancus_is_outside_sm(SM_NAME, (void *) conn_idx, sizeof(uint16_t)) ) {
      return 1;
    }

    // Note: make sure we only use AD_SIZE bytes of the buffer `ad`
    conn_index conn_id = (ad[0] << 8) | ad[1];
    io_index io_id = (ad[2] << 8) | ad[3];
    uint16_t nonce = (ad[4] << 8) | ad[5];

    // check if there is still space left in the array
    if (__sm_num_connections == SM_MAX_CONNECTIONS) {
      return 2;
    }

    // check parameters
    if(nonce != __sm_num_connections || io_id >= SM_NUM_INPUTS) {
      return 3;
    }

    Connection *conn = &__sm_io_connections[__sm_num_connections];
    *conn_idx = __sm_num_connections;

    if (!sancus_unwrap(ad, AD_SIZE, cipher, SANCUS_KEY_SIZE, tag, conn->key)) {
      return 4;
    }

    __sm_num_connections++;
    conn->io_id = io_id;
    conn->conn_id = conn_id;
    conn->nonce = 0;

    return 0;
}
