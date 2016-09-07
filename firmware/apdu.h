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

#include "ccid.h"
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

// Helper macro to evaluate arguments
#define SPLAT(MACRO, ...)  MACRO(__VA_ARGS__)

// APDU ICC Answer-To-Reset
#define APDU_ICC_ATR  0x3B, 0x00
#define APDU_ICC_ATR_SIZE  sizeof((uint8_t []) { APDU_ICC_ATR })

// APDU commands
#define APDU_VERIFY      0x20
#define APDU_SELECT_FILE 0xA4
#define APDU_GET_DATA    0xCA
#define APDU_PUT_DATA    0xDA

// APDU OpenPGP Application ID
#define APDU_PGP_APPLICATION_ID  0xD2, 0x76, 0x00, 0x01, 0x24

#define APDU_PGP_VERSION       0x0003
#define APDU_PGP_MANUFACTURER  0x4c53

// APDU OpenPGP commands
static const uint8_t APDU_PGP_COMMAND_SELECT[] = { 0x00, APDU_SELECT_FILE, 0x04, 0x00, 0x06, APDU_PGP_APPLICATION_ID, 0x01 };

// APDU OpenPGP password configuration
#define PGP_PW1_LENGTH  0b0110110
#define PGP_PW3_LENGTH  (PGP_PW1_LENGTH)

// APDU OpenPGP data object tags
#define APDU_ICC_DO_AID_TAG            0x4F
#define APDU_ICC_DO_NAME_TAG           0x5B
#define APDU_ICC_DO_EXTENDED_CAPS_TAG  0xC0
#define APDU_ICC_DO_PW_STATUS_TAG      0xC4
#define APDU_ICC_DO_FINGERPRINTS_TAG   0xC5

#define APDU_ICC_DO_SECURITY_SUPPORT_TEMPL_TAG    0x7A
#define APDU_ICC_DO_CARDHOLDER_RELATED_DATA_TAG   0x65
#define APDU_ICC_DO_APPLICATION_RELATED_DATA_TAG  0x6E

#define APDU_ICC_DO_ALGORITHM_ATTRS_TAG(index)   (0xC1 + index)

// OpenPGP algorithms
#define PGP_ECDSA_ALGO  19
#define PGP_EDDSA_ALGO  22

#define PGP_ED25519_OID    0x2B, 0x06, 0x01, 0x04, 0x01, 0x47, 0x01
#define PGP_ED25519_ALGO   (PGP_EDDSA_ALGO)
#define PGP_NISTP256_OID   0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
#define PGP_NISTP256_ALGO  (PGP_ECDSA_ALGO)

// APDU status codes
#define APDU_SUCCESS         0x90, 0x00
#define APDU_PW_WRONG        0x69, 0x82
#define APDU_FCN_NO_SUPPORT  0x6A, 0x81
#define APDU_FILE_NOT_FOUND  0x6A, 0x82
#define APDU_DATA_NOT_FOUND  0x6A, 0x88
#define APDU_NOT_SUPPORTED   0x91, 0x1C

// APDU helper macros
#define  APDU_DATA_OBJECT(tag)  \
	case APDU_ICC_DO_ ## tag ## _TAG:  \
		memcpy(response.abData, &APDU_PGP_ ## tag, sizeof(APDU_PGP_ ## tag));  \
		response.dwLength = sizeof(APDU_PGP_ ## tag);  \
		break

#define  APDU_DATA_OBJECT_CONSTRUCT_INIT(tag)  \
	case APDU_ICC_DO_ ## tag ## _TAG:  \
		_APDU_DATA_OBJECT_CONSTRUCT(&response, APDU_ICC_DO_ ## tag ## _TAG, NULL, 0);  \
		response.abData[response.dwLength++] = 0x00;

#define  APDU_DATA_OBJECT_CONSTRUCT(tag)  \
	_APDU_DATA_OBJECT_CONSTRUCT(&response, APDU_ICC_DO_ ## tag ## _TAG,  \
		(const uint8_t *) &APDU_PGP_ ## tag, sizeof(APDU_PGP_ ## tag))

#define  APDU_DATA_OBJECT_CONSTRUCT_OTHER(tag, data, length)  \
	_APDU_DATA_OBJECT_CONSTRUCT(&response, APDU_ICC_DO_ ## tag ## _TAG,  \
		(const uint8_t *) data, length)

static inline void _APDU_DATA_OBJECT_CONSTRUCT(struct RDR_to_PC_DataBlock *response, uint16_t tag, const uint8_t *data, uint8_t length) {
	// Tag
	if ((tag >> 8 & 0x1F) == 0x1F)
		response->abData[response->dwLength++] = tag >> 8;
	response->abData[response->dwLength++] = tag & 0xFF;

	// Length
	if (length >= 0x80)
		response->abData[response->dwLength++] = 0x81;
	response->abData[response->dwLength++] = length;

	// Data
	if (length) {
		memcpy(&response->abData[response->dwLength], data, length);
		response->dwLength += length;
	}
}

#define APDU_DATA_OBJECT_CONSTRUCT_END()  _APDU_DATA_OBJECT_CONSTRUCT_END(&response);

static inline void _APDU_DATA_OBJECT_CONSTRUCT_END(struct RDR_to_PC_DataBlock *response) {
	uint8_t offset = 0;
	if ((response->abData[offset++] >> 8 & 0x1F) == 0x1F)
		++offset;

	uint8_t size = response->dwLength - offset;
	if (size >= 0x80)
		response->abData[offset++] = 0x81;
	response->abData[offset++] = size;
}

#define _APDU_RETURN(response, SW1, SW2)  \
	do {  \
		response.dwLength += 2;  \
		response.abData[response.dwLength - 2] = SW1;  \
		response.abData[response.dwLength - 1] = SW2;  \
	} while (0)

#define  APDU_RETURN(response, type)      SPLAT(_APDU_RETURN, response, APDU_ ## type)

#define APDU_CHECK(buffer, length, APDU) (sizeof((APDU)) == (length) && memcmp((buffer), (APDU), (length)) == 0)

struct APDU_REQUEST {
	uint8_t CLA;
	uint8_t INS;
	uint8_t P1;
	uint8_t P2;
	uint8_t Lc;
} __attribute__((packed));

struct APDU_STATUS {
	uint8_t SW1;
	uint8_t SW2;
} __attribute__((packed));

// APDU OpenPGP data objects (DOs)
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

struct APDU_ICC_DO_FINGERPRINTS {
	uint8_t Sig[20];
	uint8_t Dec[20];
	uint8_t Aut[20];
} __attribute__((packed));

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
} __attribute__((packed));
extern const struct APDU_ICC_DO_EXTENDED_CAPS APDU_PGP_EXTENDED_CAPS;


#endif
