#include "reactive_stubs_support.h"

uint16_t SM_ENTRY(SM_NAME) __sm_set_key(const uint8_t* ad, const uint8_t* cipher,
                                    const uint8_t* tag, uint16_t *conn_idx)
{
    conn_index conn_id = (ad[0] << 8) | ad[1];
    io_index io_id = (ad[2] << 8) | ad[3];
    uint16_t nonce = (ad[4] << 8) | ad[5];

    if (__sm_num_connections == SM_MAX_CONNECTIONS) {
      return 1;
    }

    if(nonce != __sm_num_connections) {
      return 2;
    }

    Connection *conn = &__sm_io_connections[__sm_num_connections];
    *conn_idx = __sm_num_connections;

    if (!sancus_unwrap(ad, 6, cipher, SANCUS_KEY_SIZE, tag, conn->key)) {
      return 3;
    }

    __sm_num_connections++;
    conn->io_id = io_id;
    conn->conn_id = conn_id;
    conn->nonce = 0;

    return 0;
}
