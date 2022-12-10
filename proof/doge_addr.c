/*
 * Name: doge_addr.c
 * Author: Tan Teik Guan
 * Description: To calculate the address from the private key (suitable for bitcoin, dogecoin). Segwit not yet supported
 * Version: 0.1
 * 
 * Copyright (C) 2022. pQCee
 *
 * “Commons Clause” License Condition v1.0
 *
 * The Software is provided to you by the Licensor under the License, as defined below, subject to the following 
 * condition.
 *
 * Without limiting other conditions in the License, the grant of rights under the License will not include, and 
 * the License does not grant to you, the right to Sell the Software.
 *
 * For purposes of the foregoing, “Sell” means practicing any or all of the rights granted to you under the License 
 * to provide to third parties, for a fee or other consideration (including without limitation fees for hosting or 
 * consulting/ support services related to the Software), a product or service whose value derives, entirely or 
 * substantially, from the functionality of the Software. Any license notice or attribution required by the License 
 * must also include this Commons Clause License Condition notice.
 *
 * Software: dogecoin_addr 
 *
 * License: BSD 2-Clause 
 *
 * Licensor: pQCee Pte Ltd 
 *
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <openssl/rand.h>

int debug = 0;

/**
 * Copyright (c) 2012-2014 Luke Dashjr
 * Copyright (c) 2013-2014 Pavol Rusnak
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

const char b58digits_ordered[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const int8_t b58digits_map[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,
    8,  -1, -1, -1, -1, -1, -1, -1, 9,  10, 11, 12, 13, 14, 15, 16, -1, 17, 18,
    19, 20, 21, -1, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1,
    -1, -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46, 47, 48,
    49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1,
};

int b58tobin(void *bin, size_t *binszp, const char *b58) {
  size_t binsz = *binszp;
  size_t retsz = 0;
  if (binsz == 0) {
    return 0;
  }
  const unsigned char *b58u = (const unsigned char *)b58;
  unsigned char *binu = bin;
  size_t outisz = (binsz + 3) / 4;
  uint32_t outi[outisz];
  uint64_t t;
  uint32_t c;
  size_t i, j;
  uint8_t bytesleft = binsz % 4;
  uint32_t zeromask = bytesleft ? (0xffffffff << (bytesleft * 8)) : 0;
  unsigned zerocount = 0;
  size_t b58sz;

  b58sz = strlen(b58);
  memset(outi,0, sizeof(outi));

  // Leading zeros, just count
  for (i = 0; i < b58sz && b58u[i] == '1'; ++i) ++zerocount;

  for (; i < b58sz; ++i) {
    if (b58u[i] & 0x80)
      // High-bit set on invalid digit
      return 0;
    if (b58digits_map[b58u[i]] == -1)
      // Invalid base58 digit
      return 0;
    c = (unsigned)b58digits_map[b58u[i]];
    for (j = outisz; j--;) {
     t = ((uint64_t)outi[j]) * 58 + c;
      c = (t & 0x3f00000000) >> 32;
      outi[j] = t & 0xffffffff;
    }
    if (c)
      // Output number too big (carry to the next int32)
      return 0;
    if (outi[0] & zeromask)
      // Output number too big (last int32 filled too far)
      return 0;
  }

  j = 0;
  switch (bytesleft) {
    case 3:
      *(binu++) = (outi[0] & 0xff0000) >> 16;
      //-fallthrough
    case 2:
      *(binu++) = (outi[0] & 0xff00) >> 8;
      //-fallthrough
    case 1:
      *(binu++) = (outi[0] & 0xff);
      ++j;
    default:
      break;
  }
  for (; j < outisz; ++j) {
    *(binu++) = (outi[j] >> 0x18) & 0xff;
    *(binu++) = (outi[j] >> 0x10) & 0xff;
    *(binu++) = (outi[j] >> 8) & 0xff;
    *(binu++) = (outi[j] >> 0) & 0xff;
  }

  // Count canonical base58 byte count
  binu = bin;
  for (i = 0; i < binsz; ++i) {
    if (binu[i]) {
      if (zerocount > i) {
        /* result too large */
        return 0;
      }
      break;
    }
    --*binszp;
  }
  *binszp += zerocount;

  return 1;
}

int b58enc(char *b58, size_t *b58sz, const void *data, size_t binsz) {
  const uint8_t *bin = data;
  int carry;
  ssize_t i, j, high, zcount = 0;
  size_t size;

  while (zcount < (ssize_t)binsz && !bin[zcount]) ++zcount;

  size = (binsz - zcount) * 138 / 100 + 1;
  uint8_t buf[size];
  memset(buf,0, size);

  for (i = zcount, high = size - 1; i < (ssize_t)binsz; ++i, high = j) {
    for (carry = bin[i], j = size - 1; (j > high) || carry; --j) {
      carry += 256 * buf[j];
      buf[j] = carry % 58;
      carry /= 58;
    }
  }

  for (j = 0; j < (ssize_t)size && !buf[j]; ++j)
    ;

  if (*b58sz <= zcount + size - j) {
    *b58sz = zcount + size - j + 1;
    return 0;
  }
  if (zcount) memset(b58, '1', zcount);
  for (i = zcount; j < (ssize_t)size; ++i, ++j)
    b58[i] = b58digits_ordered[buf[j]];
  b58[i] = '\0';
  *b58sz = i + 1;

  return 1;
}


int main(int argc, char * argv[])
{
	EC_KEY * key;
	BN_CTX * bnctx;
	EC_POINT * pubkey;
	BIGNUM * p;
	unsigned char keybuf[1000];
	unsigned long int keybuflen = sizeof(keybuf);
	unsigned char pubkeybuf[1000];
	unsigned long int pubkeybuflen = sizeof(pubkeybuf);
	unsigned char tempc;
	SHA256_CTX shactx;
	unsigned char shahash[SHA256_DIGEST_LENGTH];
	int i;
	RIPEMD160_CTX ripectx;
	unsigned char ripehash[RIPEMD160_DIGEST_LENGTH];
	unsigned char addrbuf[25];
	char addrstr[1000];
	unsigned long int addrstrlen;
	int compressed = 1;

	if (argc != 4)
	{
		printf("Usage: %s <format 1=hex, 2=wif> <private key> <prefix e.g. 1E, 00, 6f>\n", argv[0]);
		return -1;
	}

	if (atoi(argv[1])==1)
	{
		for (i=0;i<strlen(argv[2]);i+=2)
		{
			tempc = 0;
			if ((argv[2][i]>='0') && (argv[2][i]<='9'))
				tempc = argv[2][i] - '0';
			else if ((argv[2][i]>='a') && (argv[2][i]<='f'))
				tempc = argv[2][i] - 'a' + 10;
			else if ((argv[2][i]>='A') && (argv[2][i]<='F'))
				tempc = argv[2][i] - 'A' + 10;
			tempc <<= 4;
			if ((argv[2][i+1]>='0') && (argv[2][i+1]<='9'))
				tempc += argv[2][i+1] - '0';
			else if ((argv[2][i+1]>='a') && (argv[2][i+1]<='f'))
				tempc += argv[2][i+1] - 'a' + 10;
			else if ((argv[2][i+1]>='A') && (argv[2][i+1]<='F'))
				tempc += argv[2][i+1] - 'A' + 10;
			keybuf[1+i/2] = tempc; // to account for 0x80
		}
		keybuflen = strlen(argv[2])/2 +1;
	}
	else if (atoi(argv[1]) ==2)
	{
		keybuflen = (unsigned long int) 38;
		if (!b58tobin(keybuf,&keybuflen,argv[2]))
		{
			printf("b58tobin error\n");
			return -1;
		}
		if (keybuflen == 37)
			compressed = 0;
	}
	if (debug)
	{
		printf("key len %ld\n",keybuflen);
		printf("key : ");
		for (i=0;i<(int)keybuflen;i++)
			printf("%02X",keybuf[i]);
		printf("\n");
	}
	bnctx = BN_CTX_new();

	keybuflen = 32;

	p = BN_bin2bn(keybuf+1,keybuflen,NULL);
	
	key = EC_KEY_new_by_curve_name(NID_secp256k1);
	pubkey = EC_POINT_new(EC_KEY_get0_group(key));

//	if (!EC_KEY_oct2priv(key,keybuf,(int)keybuflen))
//	if (!EC_KEY_generate_key(key))	
	if (!EC_KEY_set_private_key(key,p))
	{
		printf("set_private_key error\n");
		return -1;
	}

	if (!EC_POINT_mul(EC_KEY_get0_group(key), pubkey, p, NULL, NULL, NULL))
	{
		printf("point_mul error\n");
		return -1;
	}

	if (!EC_KEY_set_public_key(key,pubkey))
	{
		printf("set_public_key error\n");
		return -1;
	}

	if (!EC_KEY_check_key(key))
	{
		printf("checkkey error\n");
		return -1;
	}

		
	pubkeybuflen = EC_POINT_point2oct(EC_KEY_get0_group(key),EC_KEY_get0_public_key(key),(compressed)?POINT_CONVERSION_COMPRESSED:POINT_CONVERSION_UNCOMPRESSED,pubkeybuf, sizeof(pubkeybuf), bnctx);
	if (!pubkeybuflen)
	{
		printf("point2oct error\n");
		return -1;
	}
	BN_free(p);
	EC_POINT_free(pubkey);
	BN_CTX_free(bnctx);
	
	if (debug)
	{
		printf("pubkey len %ld\n",pubkeybuflen);
		printf("pubkey : ");
		for (i=0;i<(int)pubkeybuflen;i++)
			printf("%02X",pubkeybuf[i]);
		printf("\n");
	}
	SHA256_Init(&shactx);
	SHA256_Update(&shactx,pubkeybuf,pubkeybuflen);
	SHA256_Final(shahash,&shactx);
	if (debug)
	{
		printf("after sha256 : ");
		for (i=0;i<(int)sizeof(shahash);i++)
			printf("%02X",shahash[i]);
		printf("\n");
	}

	RIPEMD160_Init(&ripectx);
	RIPEMD160_Update(&ripectx,shahash,sizeof(shahash));
	RIPEMD160_Final(ripehash,&ripectx);

	if (debug)
	{
		printf("after ripemd160: ");
		for (i=0;i<sizeof(ripehash);i++)
			printf("%02X",ripehash[i]);
		printf("\n");
	}


	addrbuf[0] = 0;
	tempc = 0;
	if ((argv[3][0]>='0') && (argv[3][0]<='9'))
		tempc = argv[3][0] - '0';
	else if ((argv[3][0]>='a') && (argv[3][0]<='f'))
		tempc = argv[3][0] - 'a' + 10;
	else if ((argv[3][0]>='A') && (argv[3][0]<='F'))
		tempc = argv[3][0] - 'A' + 10;
	if (argv[3][1] != 0)
	{
		tempc<<=4;
		if ((argv[3][1]>='0') && (argv[3][1]<='9'))
			tempc += argv[3][1] - '0';
		else if ((argv[3][1]>='a') && (argv[3][1]<='f'))
			tempc += argv[3][1] - 'a' + 10;
		else if ((argv[3][1]>='A') && (argv[3][1]<='F'))
			tempc += argv[3][1] - 'A' + 10;
	}
	addrbuf[0] = tempc;

	memcpy(&(addrbuf[1]),ripehash,20);

	SHA256_Init(&shactx);
	SHA256_Update(&shactx,addrbuf,21);
	SHA256_Final(shahash,&shactx);
	SHA256_Init(&shactx);
	SHA256_Update(&shactx,shahash,sizeof(shahash));
	SHA256_Final(shahash,&shactx);

	memcpy(&(addrbuf[21]),shahash,4);

	addrstrlen = sizeof(addrstr);
	memset(addrstr,0,sizeof(addrstr));
	if (!b58enc(addrstr, &addrstrlen, addrbuf, 25)) 
	{
		printf("b58enc error\n");
		return -1;
	}

	printf("address: %s\n",addrstr);


}



