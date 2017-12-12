/*
 * This file is part of the IOTA-TREZOR project.
 *
 * Copyright (C) 2017 Bart Slinger <bartslinger@gmail.com>
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

#ifndef __IOTA_H__
#define __IOTA_H__

#include <stdint.h>
#include <stdbool.h>
#include "fsm.h"
#include "gettext.h"
#include "layout2.h"
#include "messages.h"
#include "storage.h"

// "IOTA" in hex
#define IOTA_KEY_PATH 0x494f5441

struct iota_data_struct {
	char seed[81];
	bool seed_ready;
	HDNode* node;
};

typedef struct {
	bool ready_for_signing;
	char receiving_address[81];
	uint32_t input_address_index;
	char input_address[81];
	uint32_t remainder_address_index;
	char remainder_address[81];
	uint64_t timestamp;
	uint64_t transfer_amount;
	uint64_t balance;
	char tag[27];
} iota_transaction_details_type;

bool iota_initialize(HDNode *node);
const char *iota_get_seed(void);
void iota_address_from_seed_with_index(uint32_t index, bool display, char public_address[]);
bool iota_sign_transaction(iota_transaction_details_type* transaction_details, char bundle_hash[], char first_signature[], char second_signature[]);

#endif // __IOTA_H__
