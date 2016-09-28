/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2016 Fabian Schuh <Fabian@chainsquad.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "steem.h"
#include "fsm.h"
#include "layout2.h"
#include "messages.h"
#include "transaction.h"
#include "ecdsa.h"
#include "protect.h"
#include "crypto.h"
#include "secp256k1.h"
#include "util.h"
#include "bip32.h"
#include "sha2.h"

#if USE_STEEM

// Test for Canonical signatures
int is_canonical(uint8_t by, uint8_t sig[64])
{
 (void) by;
	return !(sig[0] & 0x80)
	       && !(sig[0] == 0 && !(sig[1] & 0x80))
	       && !(sig[32] & 0x80)
	       && !(sig[32] == 0 && !(sig[33] & 0x80));
}

uint32_t varint(uint32_t len, uint8_t *out)
{
    return ser_length(len, out);
}

uint8_t steem_ser_amount(SHA256_CTX *ctx, uint64_t amount, char *asset)
{
    uint8_t precision;
    if (!strcmp(asset, "SBD")) {
        precision = 3;
    } else {
        return 1;
    }

    sha256_Update(ctx, (const uint8_t *) &amount, 8);
    sha256_Update(ctx, &precision, 1);

    uint8_t myasset[8] = {0};
    memcpy(myasset, asset, strlen(asset));
    sha256_Update(ctx, (const uint8_t *) myasset, 7);
    return 0;
}

void gph_ser_bytes(SHA256_CTX *ctx, uint8_t * msg, size_t msglen)
{
    sha256_Update(ctx, msg, msglen);
}

void gph_ser_int32(SHA256_CTX *ctx, uint32_t i)
{
    sha256_Update(ctx, (const uint8_t *) &i, 4);
}

void gph_ser_int16(SHA256_CTX *ctx, uint16_t i)
{
    sha256_Update(ctx, (const uint8_t *) &i, 2);
}

void gph_ser_varint(SHA256_CTX *ctx, uint8_t i)
{
    uint8_t buf[5];
    uint8_t buflen = 0;
    buflen = varint(i, buf);
    sha256_Update(ctx, buf, buflen);
}

void gph_ser_string(SHA256_CTX *ctx, const char *msg)
{
    gph_ser_varint(ctx, strlen(msg));
    sha256_Update(ctx, (const uint8_t *) msg, strlen(msg));
}

int graphene_sign_digest(HDNode *node, uint8_t* digest, uint8_t *signature)
{
    uint8_t pby;
    if(ecdsa_sign_digest(node->curve->params, node->private_key, digest, signature + 1, &pby, is_canonical))
    {
        fsm_sendFailure(FailureType_Failure_Other, "Signing failed");
        return 1;
    }

    signature[0] = 27 + pby + 4;
    return 0;
}

// Allow for Variable precision
const char *format_amount(uint64_t amount, int precision, char *buf)
{
	uint64_t a = amount, b = 1;
	int i;
	for (i = 0; i < precision; i++) {
		buf[16 - i] = '0' + (a / b) % 10;
		b *= 10;
	}
    buf[16-precision] = '.';
	for (i = precision + 1; i < 16; i++) {
		buf[16 - i] = '0' + (a / b) % 10;
		b *= 10;
	}
	i = 17;
	while (i > 10 && buf[i - 1] == '0') { // drop trailing zeroes
		i--;
	}
    if (buf[i - 1] == '.') --i; // drop trailing dot
	buf[i] = 0;

	const char *r = buf;
	while (*r == '0' && *(r + 1) != '.') r++; // drop leading zeroes
    return r;
}

void layout_steem_confirm_transfer(char * from, char * to, char * asset, uint64_t amount)
{
    char buf[17] = "0000000000000000";
    const char * amount_str = format_amount(amount, 3, buf);
    layoutDialogSwipe(&bmp_icon_question,
        "Cancel",
        "Confirm",
        NULL,
        "Confirm transfer",
        from,
        to,
        amount_str,
        asset,
        NULL
    );
}


#endif // USE_STEEM
