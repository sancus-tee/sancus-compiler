#ifndef _SPONGENT_H_
#define _SPONGENT_H_

#include <cstdint>


#if		defined(_SPONGENT088080008_)
#define rate		8
#define capacity	80
#define hashsize	88
#define nRounds		45
#define version		88808

#elif	defined(_SPONGENT088176088_)
#define rate		88
#define capacity	176
#define hashsize	88
#define nRounds		135
#define version		8817688

#elif   defined(_SPONGENT128128008_)
#define rate		8
#define capacity	128
#define hashsize	128
#define nRounds		70
#define version		1281288

#elif   defined(_SPONGENT128256128_)
#define rate		128
#define capacity	256
#define hashsize	128
#define nRounds		195
#define version		128256128

#elif   defined(_SPONGENT160160016_)
#define rate		16
#define capacity	160
#define hashsize	160
#define nRounds		90
#define version		16016016

#elif   defined(_SPONGENT160160080_)
#define rate		80
#define capacity	160
#define hashsize	160
#define nRounds		120
#define version		16016080

#elif   defined(_SPONGENT160320160_)
#define rate		160
#define capacity	320
#define hashsize	160
#define nRounds		240
#define version		160320160

#elif	defined(_SPONGENT224224016_)
#define rate		16
#define capacity	224
#define hashsize	224
#define nRounds		120
#define version		22422416

#elif	defined(_SPONGENT224224112_)
#define rate		112
#define capacity	224
#define hashsize	224
#define nRounds		170
#define version		224224112

#elif	defined(_SPONGENT224448224_)
#define rate		224
#define capacity	448
#define hashsize	224
#define nRounds		340
#define version		224448224

#elif	defined(_SPONGENT256256016_)
#define rate		16
#define capacity	256
#define hashsize	256
#define nRounds		140
#define version		25625616

#elif	defined(_SPONGENT256256128_)
#define rate		128
#define capacity	256
#define hashsize	256
#define nRounds		195
#define version		256256128

#elif	defined(_SPONGENT256512256_)
#define rate		256
#define capacity	512
#define hashsize	256
#define nRounds		385
#define version		256512256
#endif

#define R_SizeInBytes 	(rate / 8)
#define nBits 			(capacity + rate)
#define nSBox 			nBits/8

typedef unsigned char 		BitSequence;
typedef unsigned long long 	DataLength;

typedef uint64_t bit64;
typedef uint32_t bit32;
typedef uint16_t bit16;
typedef uint8_t  bit8;

#define GET_BIT(x,y) (x >> y) & 0x1

typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHBITLEN = 2 } HashReturn;

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

#endif /* spongent.h */












