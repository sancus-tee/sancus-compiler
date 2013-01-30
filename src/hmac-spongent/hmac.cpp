#include <cstring>

#include "spongent.h"

#define KeySize hashsize

extern "C" void hmac(const BitSequence* key,
                     const BitSequence* msg, DataLength msgLen,
                     BitSequence* out)
{
    BitSequence outerMsg[KeySize / 8 + hashsize / 8];
    BitSequence* innerMsg = new BitSequence[KeySize / 8 + msgLen];

    for (DataLength i = 0; i < KeySize / 8; i++)
    {
        outerMsg[i] = key[i] ^ 0x5c;
        innerMsg[i] = key[i] ^ 0x36;
    }

    memcpy(innerMsg + KeySize / 8, msg, msgLen);
    SpongentHash(innerMsg, msgLen * 8 + KeySize, outerMsg + KeySize / 8);
    SpongentHash(outerMsg, sizeof(outerMsg) * 8, out);

    delete[] innerMsg;
}

extern "C" void hkdf(const BitSequence* key,
                     const BitSequence* msg, DataLength msgLen,
                     BitSequence* out)
{
    BitSequence* hmac_msg = new BitSequence[msgLen + 1];
    memcpy(hmac_msg, msg, msgLen);
    hmac_msg[msgLen] = 0x01;
    hmac(key, hmac_msg, msgLen + 1, out);
    delete[] hmac_msg;
}
