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

#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef struct {
	uint8_t CLA;
	uint8_t INS;
	uint8_t P1;
	uint8_t P2;
	uint8_t Lc;

	uint8_t data[];
} __attribute__((packed)) APDU_HEADER;

enum {
	APDU_VERIFY = 0x20,
	APDU_SELECT_FILE = 0xA4,
	APDU_GET_DATA = 0xCA,
	APDU_PUT_DATA = 0xDA,
};

typedef enum {
	APDU_SECURITY_COND_FAIL   = 0x6982, // Security condition not satisfied
	APDU_PARAM_DATA_INCORRECT = 0x6A80, // The parameters in the data field are incorrect.
	APDU_FCN_NOT_SUPPORTED    = 0x6A81, // Function not supported
	APDU_FILE_NOT_FOUND       = 0x6A82, // File not found
	APDU_DATA_NOT_FOUND       = 0x6A88, // Referenced data not found
	APDU_SUCCESS              = 0x9000, // Command successfully executed (OK)
	APDU_NOT_SUPPORTED        = 0x911C, // Command code not supported
	APDU_UNRECOVERABLE        = 0x91A1, // Unrecoverable error within application
} APDU_STATUS;

static inline void APDU_SW(struct RDR_to_PC_DataBlock *response, const APDU_STATUS status) {
	response->abData[response->dwLength++] = status >> 8 & 0xFF;
	response->abData[response->dwLength++] = status >> 0 & 0xFF;
}

static inline void APDU_WRITE(struct RDR_to_PC_DataBlock *response, const void *data, const uint8_t length) {
	if (data != NULL && length > 0) {
		memcpy(&response->abData[response->dwLength], data, length);
		response->dwLength += length;
	}
}

static inline void APDU_CONSTRUCT(struct RDR_to_PC_DataBlock *response, const uint16_t tag, const void *data, const uint8_t length) {
	// Tag
	if ((tag >> 8 & 0x1F) == 0x1F)
		response->abData[response->dwLength++] = tag >> 8;
	response->abData[response->dwLength++] = tag & 0xFF;

	// Length
	if (length >= 0x80)
		response->abData[response->dwLength++] = 0x81;
	response->abData[response->dwLength++] = length;

	// Data
	APDU_WRITE(response, data, length);
}

static inline void APDU_CONSTRUCT_END(struct RDR_to_PC_DataBlock *response) {
	uint8_t offset = 0;

	if ((response->abData[offset++] & 0x1F) == 0x1F)
		++offset;

	const uint8_t size = response->dwLength - offset - 1;
	if (size >= 0x80)
		response->abData[offset++] = 0x81;

	response->abData[offset++] = size;
}

typedef struct {
	uint8_t  RID[5];
	uint8_t  Application;
	uint16_t Version;
	uint16_t Manufacturer;
	uint32_t SerialNumber;
	uint8_t  RFU[2];
} __attribute__((packed)) ISO7816_AID;

#endif
