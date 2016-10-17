/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2016 Fabian Schuh <fabian@chainsquad.com>
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

#ifndef __STEEM_H__
#define __STEEM_H__

#include <stdint.h>
#include <stdbool.h>
#include "messages.pb.h"
#include "bip32.h"
#include "sha2.h"
#include "layout2.h"

#if USE_STEEM

int graphene_sign_digest(HDNode *node, uint8_t* digest, uint8_t *signature);
int is_canonical(uint8_t by, uint8_t sig[64]);

void gph_ser_string(SHA256_CTX *ctx, const char *msg);
void gph_ser_varint(SHA256_CTX *ctx, uint8_t i);
void gph_ser_int32(SHA256_CTX *ctx, uint32_t i);
void gph_ser_int16(SHA256_CTX *ctx, uint16_t i);
void gph_ser_int8(SHA256_CTX *ctx, uint8_t i);
void gph_ser_bool(SHA256_CTX *ctx, bool i);
void gph_ser_bytes(SHA256_CTX *ctx, uint8_t * msg, size_t msglen);

uint8_t steem_ser_amount(SHA256_CTX *ctx, uint64_t amount, char *asset);
void layout_steem_confirm_transfer(char * from, char * to, char * asset, uint64_t amount);
void layout_steem_confirm_account_update(char* account);

#endif
#endif
