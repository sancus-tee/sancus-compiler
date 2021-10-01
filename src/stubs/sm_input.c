#include "reactive_stubs_support.h"

#include <alloca.h>
#include <stdlib.h>

void SM_ENTRY(SM_NAME) __sm_handle_input(uint16_t conn_idx,
                                         const void* payload, size_t len)
{
    if( !sancus_is_outside_sm(SM_NAME, (void *) payload, len)) {
      return;
    }

    if(conn_idx >= __sm_num_connections)
      return; // bad ID given by caller

    Connection *conn = &__sm_io_connections[conn_idx];

    if (conn->io_id >= SM_NUM_INPUTS)
      return;

    // associated data only contains the nonce, therefore we can use this
    // this trick to build the array fastly (i.e. by swapping the bytes)
    const uint16_t nonce_rev = conn->nonce << 8 | conn->nonce >> 8;
    const size_t data_len = len - SANCUS_TAG_SIZE;

    if(data_len == 0) {
      // In this case, sancus_unwrap would always fail due to some bug
      // therefore we just check if the tag is correct.
      const uint8_t *tag = payload;
      uint8_t expected_tag[SANCUS_TAG_SIZE];
      sancus_tag_with_key(conn->key, &nonce_rev, sizeof(nonce_rev), expected_tag);
      int success = 1, i;
      for(i=0; i<SANCUS_TAG_SIZE; i++) {
        if(tag[i] != expected_tag[i]) {
          success = 0;
          break;
        }
      }

      if(success) {
        conn->nonce++;
        __sm_input_callbacks[conn->io_id](NULL, 0);
      }
    }
    else {
      const uint8_t* cipher = payload;
      const uint8_t* tag = cipher + data_len;
      // TODO check for stack overflow!
      uint8_t* input_buffer = alloca(data_len);
      if (sancus_unwrap_with_key(conn->key, &nonce_rev, sizeof(nonce_rev),
                                 cipher, data_len, tag, input_buffer)) {
         conn->nonce++;
         __sm_input_callbacks[conn->io_id](input_buffer, data_len);
      }
    }
}
