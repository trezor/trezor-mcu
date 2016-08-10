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

#ifndef __APDU_H__
#define __APDU_H__

#include <stdint.h>
#include <stdbool.h>

// Helper macro to evaluate arguments
#define SPLAT(MACRO, ...)  MACRO(__VA_ARGS__)

// APDU ICC Answer-To-Reset
#define APDU_ICC_ATR  0x3B, 0x00
#define APDU_ICC_ATR_SIZE  sizeof((uint8_t []) { APDU_ICC_ATR })

// APDU commands
#define APDU_SELECT_FILE 0xA4
#define APDU_GET_DATA    0xCA

// APDU OpenPGP Application ID
#define APDU_PGP_APPLICATION_ID  0xD2, 0x76, 0x00, 0x01, 0x24

#define APDU_PGP_VERSION       0x0001
#define APDU_PGP_MANUFACTURER  0x534c

// APDU OpenPGP commands
static const uint8_t APDU_PGP_COMMAND_SELECT[] = { 0x00, APDU_SELECT_FILE, 0x04, 0x00, 0x06, APDU_PGP_APPLICATION_ID, 0x01 };

// APDU OpenPGP TREZOR configuration
#define PGP_PW1_LENGTH  9

// APDU OpenPGP data object tags
#define APDU_ICC_DO_AID_TAG           0x4F
#define APDU_ICC_DO_NAME_TAG          0x5B
#define APDU_ICC_DO_EXTENDED_CAPS_TAG 0xC0
#define APDU_ICC_DO_PW_STATUS_TAG     0xC4

#define APDU_ICC_DO_ALGORITHM_ATTRS_TAG(index)  (0xC1 + index)

// OpenPGP algorithms
#define PGP_ECDSA_ALGO  19
#define PGP_EDDSA_ALGO  22

#define PGP_ED25519_OID    0x2B, 0x06, 0x01, 0x04, 0x01, 0x47, 0x01
#define PGP_ED25519_ALGO   (PGP_EDDSA_ALGO)
#define PGP_NISTP256_OID   0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
#define PGP_NISTP256_ALGO  (PGP_ECDSA_ALGO)

// APDU status codes
#define APDU_SUCCESS         0x90, 0x00
#define APDU_FILE_NOT_FOUND  0x6A, 0x82
#define APDU_DATA_NOT_FOUND  0x6A, 0x88
#define APDU_NOT_SUPPORTED   0x91, 0x1C

// APDU helper macros
#define  APDU_DATA_OBJECT(tag)  \
	case APDU_ICC_DO_ ## tag ## _TAG:  \
		memcpy(response.abData, &APDU_PGP_ ## tag, sizeof(APDU_PGP_ ## tag));  \
		response.dwLength = sizeof(APDU_PGP_ ## tag);  \
		break

#define _APDU_RETURN(response, SW1, SW2)  do { response.dwLength = 2; response.abData[0] = SW1; response.abData[1] = SW2; } while (0)
#define  APDU_RETURN(response, type)      SPLAT(_APDU_RETURN, response, APDU_ ## type)

#define APDU_CHECK(buffer, length, APDU) (sizeof((APDU)) == (length) && memcmp((buffer), (APDU), (length)) == 0)

// APDU OpenPGP data objects (DOs)
struct APDU_STATUS {
	uint8_t SW1;
	uint8_t SW2;
} __attribute__((packed));

struct APDU_ICC_DO_AID {
	uint8_t  RID[5];
	uint8_t  application;
	uint16_t version;
	uint16_t manufacturer;
	uint32_t serialNumber;
	uint8_t  RFU[2];

	struct APDU_STATUS status;
} __attribute__((packed));

struct APDU_PGP_PW_FORMAT {
	unsigned int length : 7;
	unsigned int type : 1;
} __attribute__((packed));

struct APDU_ICC_DO_PW_STATUS {
	uint8_t validity;

	struct APDU_PGP_PW_FORMAT PW1;
	uint8_t RC;
	struct APDU_PGP_PW_FORMAT PW3;

	struct {
		uint8_t PW1;
		uint8_t RC;
		uint8_t PW3;
	} counter;

	struct APDU_STATUS status;
} __attribute__((packed));
extern const struct APDU_ICC_DO_PW_STATUS APDU_PGP_PW_STATUS;

struct APDU_ICC_DO_EXTENDED_CAPS {
	struct {
		bool secureMessaging       : 1;
		bool challenge             : 1;
		bool keyImport             : 1;
		bool mutablePWStatus       : 1;
		bool privateUse            : 1;
		bool mutableAlgorithmAttrs : 1;
		bool AES                   : 1;
		bool RFU                   : 1;
	} capabilities;

	uint8_t  secureMessagingAlgorithm;
	uint16_t maxChallengeLength;
	uint16_t maxCertLength;
	uint16_t maxSpecialDOLength;
	uint8_t  pinBlock2;
	uint8_t  RFU;

	struct APDU_STATUS status;
} __attribute__((packed));
extern const struct APDU_ICC_DO_EXTENDED_CAPS APDU_PGP_EXTENDED_CAPS;

#endif
