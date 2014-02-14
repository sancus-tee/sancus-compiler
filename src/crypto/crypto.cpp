#include "spongent.h"

extern "C" bool sancus_wrap(const BitSequence* key,
                            const BitSequence* ad, DataLength adLen,
                            const BitSequence* body, DataLength bodyLen,
                            BitSequence* cipher, BitSequence* tag)
{
    return SpongentWrap(key, ad, adLen * 8,
                        body, bodyLen * 8, cipher, tag) == SUCCESS;
}

extern "C" bool sancus_unwrap(const BitSequence* key,
                              const BitSequence* ad, DataLength adLen,
                              const BitSequence* cipher, DataLength cipherLen,
                              const BitSequence* tag, BitSequence* body)
{
    return SpongentUnwrap(key, ad, adLen * 8,
                          cipher, cipherLen * 8, body, tag) == SUCCESS;
}

extern "C" bool sancus_mac(const BitSequence* key,
                           const BitSequence* msg, DataLength msgLen,
                           BitSequence* mac)
{
    return SpongentMac(key, msg, msgLen * 8, mac) == SUCCESS;
}
