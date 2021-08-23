#include "reactive_stubs_support.h"

void SM_ENTRY(SM_NAME) __sm_attest(const uint8_t* challenge, size_t len, uint8_t *result)
{
    sancus_tag(challenge, len, result);
}
