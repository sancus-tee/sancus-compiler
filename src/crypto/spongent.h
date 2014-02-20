#ifndef _SPONGENT_H_
#define _SPONGENT_H_

#include "config.h"

#include <cstdint>

// #define _PrintState_

#define SW_RATE       16
#define SW_RATE_BYTES (SW_RATE / 8)

#define MIN_CAPACITY (SW_SECURITY * 2)
#define MIN_WIDTH    (MIN_CAPACITY + SW_RATE + 2)

#if MIN_WIDTH <= 88
#define WIDTH   88
#define nRounds 45
#define version 88808

#elif MIN_WIDTH <= 136
#define WIDTH   136
#define nRounds 70
#define version 1281288

#elif MIN_WIDTH <= 176
#define WIDTH   176
#define nRounds 90
#define version 16016016

#elif MIN_WIDTH <= 240
#define WIDTH   240
#define nRounds 120
#define version 16016080

#elif MIN_WIDTH <= 264
#define WIDTH   264
#define nRounds 135
#define version 8817688

#elif MIN_WIDTH <= 272
#define WIDTH   272
#define nRounds 140
#define version 25625616

#elif MIN_WIDTH <= 336
#define WIDTH   336
#define nRounds 170
#define version 224224112

#elif MIN_WIDTH <= 384
#define WIDTH   384
#define nRounds 195
#define version 256256128

#elif MIN_WIDTH <= 480
#define WIDTH   480
#define nRounds 240
#define version 160320160

#elif MIN_WIDTH <= 672
#define WIDTH   672
#define nRounds 340
#define version 224448224

#elif MIN_WIDTH <= 768
#define WIDTH   768
#define nRounds 385
#define version 256512256

#else
#error "Security too high"
#endif

#define rate        (SW_RATE + 2)
#define capacity    (WIDTH - rate)
#define hashsize    SW_SECURITY

#define BITS_TO_BYTES(x) (x / 8 + (x % 8 != 0))

#define R_SizeInBytes 	BITS_TO_BYTES(rate)
#define nBits 			(capacity + rate)
#define nSBox 			nBits/8
#define KEY_SIZE hashsize
#define TAG_SIZE hashsize
#define TAG_SIZE_BYTES (TAG_SIZE / 8)

typedef unsigned char 		BitSequence;
typedef unsigned long long 	DataLength;

typedef uint64_t bit64;
typedef uint32_t bit32;
typedef uint16_t bit16;
typedef uint8_t  bit8;

#define GET_BIT(x,y) (x >> y) & 0x1

typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHBITLEN = 2, BAD_TAG = 3 } HashReturn;

typedef struct {
 	BitSequence value[nSBox];					/* current Spongent state */
 	BitSequence messageblock[R_SizeInBytes];	/* message block to be input/output */
	int remainingbitlen;						/* remaining data length */
	int hashbitlen;								/* # of hashed bits so far */
} hashState;

HashReturn SpongentHash(const BitSequence *data, DataLength databitlen, BitSequence *hashval);
HashReturn Init(hashState *state, BitSequence *hashval);
HashReturn Absorb(hashState *state, const BitSequence *data, DataLength databitlen);
HashReturn Squeeze(hashState *state);
HashReturn Pad(hashState *state);

int Pi(int i);
void pLayer(hashState *state);
void Permute(hashState *state);

bit16 lCounter(bit16 lfsr);
bit16 retnuoCl(bit16 lfsr);

HashReturn SpongentWrap(const BitSequence* key,
                        const BitSequence* ad, DataLength adBitLength,
                        const BitSequence* input, DataLength bitLength,
                        BitSequence* output,
                        BitSequence* tag,
                        bool unwrap = false);

HashReturn SpongentUnwrap(const BitSequence* key,
                          const BitSequence* ad, DataLength adBitLength,
                          const BitSequence* input, DataLength bitLength,
                          BitSequence* output,
                          const BitSequence* expectedTag);

HashReturn SpongentMac(const BitSequence* key,
                       const BitSequence* input, DataLength bitLength,
                       BitSequence* mac);

#endif /* spongent.h */
