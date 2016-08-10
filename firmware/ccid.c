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


#include "usb.h"
#include "ccid.h"
#include "debug.h"
#include "storage.h"

#include <string.h>

CCID_HANDLER_INIT(IccPowerOn);
CCID_HANDLER_INIT(GetSlotStatus);
CCID_HANDLER_INIT(XfrBlock);

void ccid_read(struct ccid_header *header, const uint8_t *buf) {
	switch (header->bMessageType) {
	CCID_HANDLER_TEST(IccPowerOn);

	case PC_to_RDR_IccPowerOff_Type:
		debugLog(0, "", "PC_to_RDR_IccPowerOff");
	CCID_HANDLER_TEST(GetSlotStatus);

	CCID_HANDLER_TEST(XfrBlock);

	default:
		debugLog(0, "", "ccid_rx_callback");
		break;
	}
}

CCID_HANDLER(IccPowerOn, request, buf) {
	(void) buf;
	debugLog(0, "", __func__);

	static struct RDR_to_PC_DataBlock response = {
		.bMessageType = RDR_to_PC_DataBlock_Type,
		.dwLength = APDU_ICC_ATR_SIZE,
		.bStatus = {
			.bmICCStatus = 0,
			.bmRFU = 0,
			.bmCommandStatus = 0
		},
		.bError = 0,
		.bChainParameter = 0,
		.abData = { APDU_ICC_ATR }
	};

	response.bSlot = request->bSlot;
	response.bSeq = request->bSeq;

	CCID_TX(&response);
}

CCID_HANDLER(GetSlotStatus, request, buf) {
	(void) buf;
	// debugLog(0, "", __func__);
	CCID_CAST_RESPONSE(SlotStatus);
	CCID_TX(response);
}

CCID_HANDLER(XfrBlock, request, apdu) {
	debugLog(0, "", __func__);
	static struct RDR_to_PC_DataBlock response = {
		.bMessageType = RDR_to_PC_DataBlock_Type,
		.bStatus = {
			.bmICCStatus = 0,
			.bmRFU = 0,
			.bmCommandStatus = 0
		},
		.bError = 0,
		.bChainParameter = 0
	};

	static struct APDU_ICC_DO_AID APDU_PGP_AID = {
		.RID = { APDU_PGP_APPLICATION_ID },
		.application = 0x01,
		.version = APDU_PGP_VERSION,
		.manufacturer = APDU_PGP_MANUFACTURER,
		.RFU = { 0x00, 0x00 },

		.status = { APDU_SUCCESS }
	};
	memcpy(&APDU_PGP_AID.serialNumber, storage_uuid, sizeof(APDU_PGP_AID.serialNumber));

	const char *label = storage_getLabel();

	response.bSlot = request->bSlot;
	response.bSeq = request->bSeq;

	if (APDU_CHECK(apdu, request->dwLength, APDU_PGP_COMMAND_SELECT)) {
		APDU_RETURN(response, SUCCESS);
	} else if (apdu[1] == APDU_GET_DATA) {
		uint16_t tag = (apdu[2] << 8) + apdu[3];
		switch (tag) {
		APDU_DATA_OBJECT(AID);
		APDU_DATA_OBJECT(PW_STATUS);
		APDU_DATA_OBJECT(EXTENDED_CAPS);

		case APDU_ICC_DO_NAME_TAG:
			response.dwLength = 2;
			if (label) {
				strcpy((char *) response.abData, label);
				response.dwLength += strlen(label);
			}

			response.abData[response.dwLength - 2] = 0x90;
			response.abData[response.dwLength - 1] = 0x00;
			break;

		default:
			debugLog(0, "", "APDU GET DATA: Referenced data not found");
			APDU_RETURN(response, DATA_NOT_FOUND);
			break;
		}
	} else {
		switch (apdu[1]) {
		case APDU_SELECT_FILE:
			debugLog(0, "", "APDU SELECT FILE: File not found");
			APDU_RETURN(response, FILE_NOT_FOUND);
			break;
		default:
			debugLog(0, "", "APDU unmatched");
			APDU_RETURN(response, NOT_SUPPORTED);
			break;
		}
	}

	CCID_TX(&response);
}
