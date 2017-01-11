/*
	* SPONGENT hash function - Implementation
	* This code is placed in the public domain
	* For more information, feedback or questions, please refer to our website:
	* https://sites.google.com/site/spongenthash/

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <algorithm>
#include <iterator>
#include "spongent.h"

/* Spongent S-box */
int S[16] = { 0xe, 0xd, 0xb, 0x0, 0x2, 0x1, 0x4, 0xf, 0x7, 0xa, 0x8, 0x5, 0x9, 0xc, 0x3, 0x6};


/* Spongent eight bit S-box */
int  sBoxLayer[256] = {
	0xee, 0xed, 0xeb, 0xe0, 0xe2, 0xe1, 0xe4, 0xef, 0xe7, 0xea, 0xe8, 0xe5, 0xe9, 0xec, 0xe3, 0xe6, 
	0xde, 0xdd, 0xdb, 0xd0, 0xd2, 0xd1, 0xd4, 0xdf, 0xd7, 0xda, 0xd8, 0xd5, 0xd9, 0xdc, 0xd3, 0xd6, 
	0xbe, 0xbd, 0xbb, 0xb0, 0xb2, 0xb1, 0xb4, 0xbf, 0xb7, 0xba, 0xb8, 0xb5, 0xb9, 0xbc, 0xb3, 0xb6, 
	0x0e, 0x0d, 0x0b, 0x00, 0x02, 0x01, 0x04, 0x0f, 0x07, 0x0a, 0x08, 0x05, 0x09, 0x0c, 0x03, 0x06, 
	0x2e, 0x2d, 0x2b, 0x20, 0x22, 0x21, 0x24, 0x2f, 0x27, 0x2a, 0x28, 0x25, 0x29, 0x2c, 0x23, 0x26, 
	0x1e, 0x1d, 0x1b, 0x10, 0x12, 0x11, 0x14, 0x1f, 0x17, 0x1a, 0x18, 0x15, 0x19, 0x1c, 0x13, 0x16, 
	0x4e, 0x4d, 0x4b, 0x40, 0x42, 0x41, 0x44, 0x4f, 0x47, 0x4a, 0x48, 0x45, 0x49, 0x4c, 0x43, 0x46, 
	0xfe, 0xfd, 0xfb, 0xf0, 0xf2, 0xf1, 0xf4, 0xff, 0xf7, 0xfa, 0xf8, 0xf5, 0xf9, 0xfc, 0xf3, 0xf6, 
	0x7e, 0x7d, 0x7b, 0x70, 0x72, 0x71, 0x74, 0x7f, 0x77, 0x7a, 0x78, 0x75, 0x79, 0x7c, 0x73, 0x76, 
	0xae, 0xad, 0xab, 0xa0, 0xa2, 0xa1, 0xa4, 0xaf, 0xa7, 0xaa, 0xa8, 0xa5, 0xa9, 0xac, 0xa3, 0xa6, 
	0x8e, 0x8d, 0x8b, 0x80, 0x82, 0x81, 0x84, 0x8f, 0x87, 0x8a, 0x88, 0x85, 0x89, 0x8c, 0x83, 0x86, 
	0x5e, 0x5d, 0x5b, 0x50, 0x52, 0x51, 0x54, 0x5f, 0x57, 0x5a, 0x58, 0x55, 0x59, 0x5c, 0x53, 0x56, 
	0x9e, 0x9d, 0x9b, 0x90, 0x92, 0x91, 0x94, 0x9f, 0x97, 0x9a, 0x98, 0x95, 0x99, 0x9c, 0x93, 0x96, 
	0xce, 0xcd, 0xcb, 0xc0, 0xc2, 0xc1, 0xc4, 0xcf, 0xc7, 0xca, 0xc8, 0xc5, 0xc9, 0xcc, 0xc3, 0xc6, 
	0x3e, 0x3d, 0x3b, 0x30, 0x32, 0x31, 0x34, 0x3f, 0x37, 0x3a, 0x38, 0x35, 0x39, 0x3c, 0x33, 0x36, 
	0x6e, 0x6d, 0x6b, 0x60, 0x62, 0x61, 0x64, 0x6f, 0x67, 0x6a, 0x68, 0x65, 0x69, 0x6c, 0x63, 0x66 
};

//--------------------------------------------------------------------------------------------

void PrintState(hashState *state)
{
	int i;
	for (i=nSBox-1; i>=0; i--)
		printf("%02X", state->value[i]);
	printf("\n");
}

//--------------------------------------------------------------------------------------------

bit16 lCounter(bit16 lfsr)
{
	switch( version ) {
		case     88808:
			lfsr = (lfsr << 1) | (((0x20 & lfsr) >> 5) ^ ((0x10 & lfsr) >> 4));
			lfsr &= 0x3f;
			break;
		case   1281288:
		case  16016016:
		case  16016080:
		case  22422416:
			lfsr = (lfsr << 1) | (((0x40 & lfsr) >> 6) ^ ((0x20 & lfsr) >> 5));
			lfsr &= 0x7f; 
			break;
		case   8817688:
		case 128256128:
		case 160320160:
		case 224224112:
		case  25625616:
		case 256256128:
			lfsr = (lfsr << 1) | (((0x80 & lfsr) >> 7) ^ ((0x08 & lfsr) >> 3) ^ ((0x04 & lfsr) >> 2) ^ ((0x02 & lfsr) >> 1));
			lfsr &= 0xff; 
			break;
		case 224448224:
		case 256512256:
			lfsr = (lfsr << 1) | (((0x100 & lfsr) >> 8) ^ ((0x08 & lfsr) >> 3));
			lfsr &= 0x1ff;
			break;
		default :
			printf("ErrorCounter\n");
			break;
	}
	return lfsr;
}

//--------------------------------------------------------------------------------------------

bit16 retnuoCl(bit16 lfsr)
{
	switch(version)
	{
		case     88808:
		case   8817688:
		case   1281288:
		case 128256128:
		case  16016016:
		case  16016080:
		case 160320160:
		case  22422416:
		case 224224112:
		case  25625616:
		case 256256128:
			lfsr = ( ((lfsr & 0x01) <<7) | ((lfsr & 0x02) << 5) | ((lfsr & 0x04) << 3) | ((lfsr & 0x08) << 1) | ((lfsr & 0x10) >> 1) | ((lfsr & 0x20) >> 3) | ((lfsr & 0x40) >> 5) | ((lfsr & 0x80) >> 7) );		
			lfsr <<= 8;
			break;
		case 224448224:	
		case 256512256:	
			lfsr = ( ((lfsr & 0x01) <<8) | ((lfsr & 0x02) << 6) | ((lfsr & 0x04) << 4) | ((lfsr & 0x08) << 2) | ((lfsr & 0x10) << 0) | ((lfsr & 0x20) >> 2) | ((lfsr & 0x40) >> 4) | ((lfsr & 0x80) >> 6) | ((lfsr & 0x100) >> 8) ); 
			lfsr <<= 7;
			break;
		default :
			printf("ErrorInverseCounter\n");
			break;			
	}	
	
	return lfsr;
}

//--------------------------------------------------------------------------------------------

int Pi(int i)
{
	if (i != nBits-1)
		return (i*nBits/4)%(nBits-1);
	else
		return nBits-1;
}

//--------------------------------------------------------------------------------------------

void pLayer(hashState *state)
{
	int	i, j, PermutedBitNo;
	bit8	tmp[nSBox], x, y;
	
	for(i = 0; i < nSBox; i++) tmp[i] = 0;
	
	for(i = 0; i < nSBox; i++){
		for(j = 0; j < 8; j++){ 
			x			= GET_BIT(state->value[i],j);
			PermutedBitNo	= Pi(8*i+j);
			y			= PermutedBitNo/8;
			tmp[y]		^= x << (PermutedBitNo - 8*y);
		}
	}	
	memcpy(state->value, tmp, nSBox);
}

//--------------------------------------------------------------------------------------------

void Permute(hashState *state)
{
	bit16	i, j, IV, INV_IV;
		
	switch(version)
	{
		case     88808:	IV = 0x05;	break;
		case   8817688:	IV = 0xC6;	break;
		case   1281288:	IV = 0x7A;	break;
		case 128256128:	IV = 0xFB;	break;
		case  16016016:	IV = 0x45;	break;
		case  16016080:	IV = 0x01;	break;
		case 160320160:	IV = 0xA7;	break;
		case  22422416:	IV = 0x01;	break;
		case 224224112:	IV = 0x52;	break;
		case 224448224:	IV = 0x105; break;
		case  25625616:	IV = 0x9e;	break;
		case 256256128:	IV = 0xfb;	break;
		case 256512256:	IV = 0x015;	break;
	}
	
	for(i = 0; i < nRounds; i++){
#ifdef _PrintState_
		printf("%3d\t", i);
		PrintState(state);
#endif
		/* Add counter values */
		state->value[0]			^= IV & 0xFF;
		state->value[1]			^= (IV >> 8) & 0xFF;
		INV_IV	= retnuoCl(IV);
		state->value[nSBox-1]	^= (INV_IV >> 8) & 0xFF;;
		state->value[nSBox-2]	^= INV_IV & 0xFF;		
		IV	= lCounter(IV);
		
		/* sBoxLayer layer */
		for ( j=0; j < nSBox; j++)	
			state->value[j] =  sBoxLayer[state->value[j]];
		
		/* pLayer */
		pLayer(state);\
	}
#ifdef _PrintState_
	printf("%3d\t", i);
	PrintState(state);
#endif	
}

//--------------------------------------------------------------------------------------------

HashReturn Init(hashState *state, BitSequence *hashval = nullptr)
{
	/* check hashsize and initialize accordingly */
// 	switch( hashsize )
// 	{
// 		case 88:		break;
// 		case 128:		break;
// 		case 160:		break;
// 		case 224:		break;
// 		case 256:		break;
//
// 		default:
// 			return BAD_HASHBITLEN;
// 	}

    memset(state->value, 0, nSBox);
    state->hashbitlen = 0;
    state->remainingbitlen = 0;

    if (hashval != nullptr)
        memset(hashval, 0, hashsize/8);

    return SUCCESS;
}

//--------------------------------------------------------------------------------------------

HashReturn Absorb(hashState *state)
{
	int i;
	for(i = 0; i < R_SizeInBytes; i++)	
		state->value[i] ^= state->messageblock[i];
 	Permute(state);
	
	return SUCCESS;
}

//--------------------------------------------------------------------------------------------

HashReturn Squeeze(hashState *state)
{
	memcpy(state->messageblock, state->value, R_SizeInBytes);
#ifdef _PrintState_
	printf("h_i\t");
	for(int i = 0; i < R_SizeInBytes; i++) 
		printf("%02X", state->messageblock[i]);
	printf("\n\n");
#endif		
	Permute(state);
	
	return SUCCESS;
}

//--------------------------------------------------------------------------------------------

HashReturn Pad(hashState *state)			
{
        int byteind = state->remainingbitlen/8; /* byte index of remaining byte */
        int bitpos = state->remainingbitlen%8; /* bit position in last byte */
        
        /* make unoccupied bits 0 */
        if(bitpos)
            state->messageblock[byteind] &= 0xff >> (8 - bitpos);

        /* add single 1-bit */
        if(bitpos)
            state->messageblock[byteind] |= 0x01 << bitpos;
        else
            state->messageblock[byteind] = 0x01;
        
        /* add 0-bits until we have rate bits */
        while(byteind!=R_SizeInBytes)
        {
                byteind++;
                state->messageblock[byteind] = 0;
        }
        return SUCCESS;
}

//--------------------------------------------------------------------------------------------

HashReturn SpongentHash(const BitSequence *data, DataLength databitlen, BitSequence *hashval)
{
	hashState  state;
	HashReturn res;
	
	/* initialize */
	res = Init(&state, hashval); 	
	if(res != SUCCESS)
		return res;	
	
	/* Absorb available message blocks */
	while(databitlen >= rate)
	{
		memcpy(state.messageblock, data, R_SizeInBytes);
#ifdef _PrintState_
	printf("\n");
	printf("m_i\t");
	for(int i = 0; i < R_SizeInBytes; i++) 
		printf("%02X", state.messageblock[i]);
	printf("\n");
#endif		
		Absorb(&state);
		databitlen -= rate;
		data += R_SizeInBytes;
	}
		
	/* Pad the remaining bits before absorbing */
	if(databitlen>0){
		memcpy(state.messageblock, data, databitlen/8 + (databitlen%8?1:0));
		state.remainingbitlen = databitlen;
		}
	else if(databitlen==0){
		memset(state.messageblock, 0, R_SizeInBytes);
		state.remainingbitlen = databitlen;
		}
	Pad(&state);
#ifdef _PrintState_
	printf("\n");
	printf("m_i\t");
	for(int i = 0; i < R_SizeInBytes; i++) 
		printf("%02X", state.messageblock[i]);
	printf("\n");
#endif		
	Absorb(&state);
	state.hashbitlen += rate;
		
	/* Squeeze data blocks */		
	while(state.hashbitlen < hashsize)
	{
		Squeeze(&state);
		memcpy(hashval, state.messageblock, R_SizeInBytes);
		state.hashbitlen += rate;
		hashval += R_SizeInBytes;
	}	

	memcpy(hashval, state.value, R_SizeInBytes);
	hashval += R_SizeInBytes;
#ifdef _PrintState_
	printf("h_i\t");
	for(int i = 0; i < R_SizeInBytes; i++) 
		printf("%02X", state.value[i]);
	printf("\n\n");
#endif		
	
	return SUCCESS;
}

HashReturn Duplexing(hashState* state,
                     BitSequence* block,
                     DataLength blockBitLength,
                     BitSequence* out = nullptr,
                     DataLength outBitsLength = SW_RATE)
{
    std::copy_n(block, BITS_TO_BYTES(blockBitLength), state->messageblock);
    state->remainingbitlen = blockBitLength;
    HashReturn ret = Pad(state);

    if (ret != SUCCESS)
        return ret;

    ret = Absorb(state);

    if (ret != SUCCESS)
        return ret;

    if (out != nullptr)
        std::copy_n(state->value, outBitsLength / 8, out);

    return SUCCESS;
}

HashReturn SpongentWrap(const BitSequence* key,
                        const BitSequence* ad, DataLength adBitLength,
                        const BitSequence* input, DataLength bitLength,
                        BitSequence* output,
                        BitSequence* tag,
                        bool unwrap)
{
    if (adBitLength % 8 != 0 || bitLength % 8 != 0)
    {
        fprintf(stderr, "Messages containing partial bytes not supported\n");
        return FAIL;
    }

    hashState state;
    HashReturn ret = Init(&state);

    if (ret != SUCCESS)
        return ret;

    BitSequence block[R_SizeInBytes];
    BitSequence duplexOut[R_SizeInBytes];
    DataLength bitsLeft = KEY_SIZE;

    while (bitsLeft > SW_RATE)
    {
        std::copy_n(key, SW_RATE_BYTES, block);
        block[SW_RATE_BYTES] = 0x01;
        ret = Duplexing(&state, block, SW_RATE + 1);

        if (ret != SUCCESS)
            return ret;

        bitsLeft -= SW_RATE;
        key += SW_RATE_BYTES;
    }

    std::copy_n(key, bitsLeft / 8, block);
    block[bitsLeft / 8] = 0x00;
    ret = Duplexing(&state, block, bitsLeft + 1);

    if (ret != SUCCESS)
        return ret;

    bitsLeft = adBitLength;

    while (bitsLeft > SW_RATE)
    {
        std::copy_n(ad, SW_RATE_BYTES, block);
        block[SW_RATE_BYTES] = 0x00;
        ret = Duplexing(&state, block, SW_RATE + 1);

        if (ret != SUCCESS)
            return ret;

        bitsLeft -= SW_RATE;
        ad += SW_RATE_BYTES;
    }

    std::copy_n(ad, bitsLeft / 8, block);
    block[bitsLeft / 8] = 0x01;
    ret = Duplexing(&state, block, bitsLeft + 1, duplexOut);

    if (ret != SUCCESS)
        return ret;

    DataLength firstBlockLength =
        std::min(bitLength, (DataLength)SW_RATE) / 8;

    for (DataLength i = 0; i < firstBlockLength; i++)
        output[i] = input[i] ^ duplexOut[i];

    bitsLeft = bitLength;

    while (bitsLeft > SW_RATE)
    {
        std::copy_n(unwrap ? output : input, SW_RATE_BYTES, block);
        block[SW_RATE_BYTES] = 0x01;
        HashReturn ret = Duplexing(&state, block, SW_RATE + 1, duplexOut);

        if (ret != SUCCESS)
            return ret;

        bitsLeft -= SW_RATE;
        input += SW_RATE_BYTES;
        output += SW_RATE_BYTES;

        DataLength blockLength = std::min(bitsLeft, (DataLength)SW_RATE) / 8;

        for (DataLength i = 0; i < blockLength; i++)
            output[i] = input[i] ^ duplexOut[i];
    }

    std::copy_n(unwrap ? output : input, bitsLeft / 8, block);
    block[bitsLeft / 8] = 0x00;
    ret = Duplexing(&state, block, bitsLeft + 1,
                    tag, std::min((DataLength)TAG_SIZE, (DataLength)SW_RATE));

    if (ret != SUCCESS)
        return ret;

    DataLength tagBitsDone = SW_RATE;
    tag += SW_RATE_BYTES;
    std::fill_n(block, sizeof(block), 0x00);

    while (tagBitsDone < TAG_SIZE)
    {
        ret = Duplexing(&state, block, 0, tag,
                        std::min(TAG_SIZE - tagBitsDone, (DataLength)SW_RATE));

        if (ret != SUCCESS)
            return ret;

        tagBitsDone += SW_RATE;
        tag += SW_RATE_BYTES;
    }

    return SUCCESS;
}

HashReturn SpongentUnwrap(const BitSequence* key,
                          const BitSequence* ad, DataLength adBitLength,
                          const BitSequence* input, DataLength bitLength,
                          BitSequence* output,
                          const BitSequence* expectedTag)
{
    BitSequence tag[TAG_SIZE_BYTES];
    HashReturn ret = SpongentWrap(key,
                                  ad, adBitLength,
                                  input, bitLength,
                                  output, tag, /*unwrap=*/true);

    if (ret != SUCCESS)
        return ret;

    if (!std::equal(std::begin(tag), std::end(tag), expectedTag))
        return BAD_TAG;

    return SUCCESS;
}

HashReturn SpongentMac(const BitSequence* key,
                       const BitSequence* input, DataLength bitLength,
                       BitSequence* mac)
{
    return SpongentWrap(key, input, bitLength, nullptr, 0, nullptr, mac);
}

//--------------------------------------------------------------------------------------------

void generateTestVectors(void)
{
	int i;
	BitSequence hashval[hashsize/8]={0};

	BitSequence message[256] = "Sponge + Present = Spongent";   

//	BitSequence message[256] = {'S', 'p', 'o', 'n', 'g', 'e', ' ', '+', ' ', 
//								'P', 'r', 'e', 's', 'e', 'n', 't', ' ', '=', ' ', 
//								'S', 'p', 'o', 'n', 'g', 'e', 'n', 't'};   	

//	BitSequence message[256] = {0x53, 0x70, 0x6F, 0x6E, 0x67, 0x65, 0x20, 0x2B, 
//								0x20, 0x50, 0x72, 0x65, 0x73, 0x65, 0x6E, 0x74, 
//								0x20, 0x3D, 0x20, 0x53, 0x70, 0x6F, 0x6E, 0x67, 0x65, 0x6E, 0x74};

	printf("Message(String)\t:%s\n", message);
	printf("Message(Hex)\t:");
	for (i = 0; i < 216/8; i++) {
		printf("%02X", message[i]);
	}
	printf("\n");
	
	DataLength databitlen = 216;		
	
	SpongentHash(message, databitlen, hashval);
	
	printf("Hash\t\t:");
	for(i=0; i<hashsize/8; i++)
		printf("%.2X",hashval[i]);
	printf("\n");		
}


//--------------------------------------------------------------------------------------------


// int main(void)
// {
// 	generateTestVectors();
// 
// 		
// 	return 0;
// }
