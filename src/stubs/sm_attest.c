#include "reactive_stubs_support.h"

uint16_t SM_ENTRY(SM_NAME) __sm_attest(const uint8_t* challenge, size_t len,
  uint8_t *result)
{
    if( !sancus_is_outside_sm(SM_NAME, (void *) challenge, len) ||
        !sancus_is_outside_sm(SM_NAME, (void *) result, SANCUS_TAG_SIZE) ) {
      return 1;
    }

    sancus_tag(challenge, len, result);
    return 0;
}
