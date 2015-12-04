#include "reactive_stubs_support.h"

void SM_ENTRY(SM_NAME) __sm_set_key(const uint8_t* ad, const uint8_t* cipher,
                                    const uint8_t* tag, uint8_t* result)
{
    uint16_t conn_id = (ad[2] << 8) | ad[3];
    ResultCode code = Ok;

    if (conn_id >= SM_NUM_CONNECTIONS)
        code = IllegalConnection;
    else if (!sancus_unwrap(ad, 4, cipher, SANCUS_KEY_SIZE, tag,
             __sm_io_keys[conn_id]))
    {
        code = MalformedPayload;
    }

    result[0] = 0;
    result[1] = code;
    uint8_t result_ad[] = {ad[0], ad[1], result[0], result[1]};
    sancus_tag(result_ad, sizeof(result_ad), result + 2);
}
