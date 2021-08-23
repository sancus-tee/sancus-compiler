#include "reactive_stubs_support.h"

#include <stdlib.h>

SM_FUNC(SM_NAME) void __sm_send_output(io_index index,
                                       const void* data, size_t len)
{
    const size_t payload_len = len + SANCUS_TAG_SIZE;

    // search for all the connections associated to the index.
    // Unfortunately, this operation is O(n) with n = number of connections
    int i;
    for (i=0; i<__sm_num_connections; i++) {
      Connection *conn = &__sm_io_connections[i];
      if(conn->io_id != index)
        continue;

      uint8_t* payload = malloc(payload_len);
      if (payload == NULL)
        continue;

      // associated data only contains the nonce, therefore we can use this
      // this trick to build the array fastly (i.e. by swapping the bytes)
      uint16_t nonce_rev = conn->nonce << 8 | conn->nonce >> 8;
      sancus_wrap_with_key(conn->key, &nonce_rev, sizeof(nonce_rev), data,
                          len, payload, payload + len);
      conn->nonce++;
      reactive_handle_output(conn->conn_id, payload, payload_len);
    }
}
