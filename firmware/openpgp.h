/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2016 Saleem Rashid <trezor@saleemrashid.com>
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

#ifndef __OPENPGP_H__
#define __OPENPGP_H__

#include "apdu.h"
#include "ccid.h"

#include <stdint.h>

void ccid_OpenPGP(const APDU_HEADER *APDU, uint8_t length, struct RDR_to_PC_DataBlock *response);

#define OPENPGP_VERSION      0x0003 // OpenPGP Card 3.0
#define OPENPGP_MANUFACTURER 0x4C53 // TODO: choose a valid value

#define OPENPGP_DERIVATION_PATH (0x80 << 24 | 'P' << 16 | 'G' <<  8 | 'P')

static const uint8_t OPENPGP_APPLICATION_ID[] = { 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01 };

// OpenPGP Algorithms
static const uint8_t OPENPGP_NISTP256[] = { 19, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static const uint8_t OPENPGP_ED25519[]  = { 22, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01 };

typedef struct {
	unsigned Length : 7; /* Max. length, for PIN format 2 always '08'
				(real PIN length up to 12 digits) */
	unsigned Type   : 1; /* 0 for UTF-8 passwords
				1 for PIN block format 2 */
} __attribute__((packed)) OPENPGP_PW_FORMAT;

typedef struct {
	uint8_t Validity; /* 00 = PW1 (no. 81) only valid for one PSO:CDS command
			   * 01 = PW1 valid for several PSO:CDS commands */

	OPENPGP_PW_FORMAT PW1; // Max. length and format of PW1 (user)
	uint8_t RC;            // Max. length of Resetting Code (RC) for PW1
	OPENPGP_PW_FORMAT PW3; // Max. length and format of PW3 (admin)

	struct { uint8_t PW1, RC, PW3; } Errors;
} __attribute__((packed)) OPENPGP_PW_STATUS;

typedef struct {
	struct {
		unsigned SecureMessaging  : 1; // Secure Messaging supported
		unsigned GetChallenge     : 1; // Support for GET CHALLENGE
		unsigned KeyImport        : 1; // Support for Key Import
		unsigned PWStatusMutable  : 1; // PW Status changeable
		unsigned PrivateUseDOs    : 1; // Support for Private use DOs
		unsigned AlgoAttrsMutable : 1; /* Algorithm attributes changeable with
		                                  PUT DATA */
		unsigned PSODEC_AES       : 1; // PSO:DEC supports AES
		unsigned RFU              : 1;
	} Capabilities;

	uint8_t  SecureMessaging;    // Secure Messaging Algorithm
	uint16_t MaxChallengeLength; /* Maximum length of a challenge supported by
	                                the command GET CHALLENGE  */
	uint16_t MaxCertLength;      // Maximum length of Cardholder Certificate
	uint16_t MaxSpecialDOLength; // Maximum length of special DOs
	uint8_t  PINBlock2;          // PIN block 2 format
	uint8_t  RFU;
} __attribute__((packed)) OPENPGP_EXTENDED_CAPS;

#endif
