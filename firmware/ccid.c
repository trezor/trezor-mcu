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


#include "ccid.h"

#include "apdu.h"
#include "debug.h"
#include "openpgp.h"
#include "usb.h"

#include <stddef.h>
#include <string.h>

static void ccid_IccPowerOn(const CCID_HEADER *request);
static void ccid_GetSlotStatus(const CCID_HEADER *request);

static void ccid_XfrBlock(const struct PC_to_RDR_XfrBlock *request);

/*
 * Smart card applications
 */
typedef enum {
	NONE = 0,

	/*
	 * OpenPGP Card 3.0 Application (firmware/openpgp.c)
	 */
	CCID_OPENPGP = 0x01,
} CCID_APPLICATION;

/*
 * Handle CCID message, expecting request->dwLength to be accurate.
 */
void ccid_rx(const CCID_HEADER *request, char tiny) {
	switch (request->bMessageType) {
		case PC_to_RDR_IccPowerOn:
			ccid_IccPowerOn(request);
			break;

		case PC_to_RDR_IccPowerOff:
		case PC_to_RDR_GetSlotStatus:
			ccid_GetSlotStatus(request);
			break;

		case PC_to_RDR_XfrBlock:
			/*
			 * CCID should NOT attempt to talk to the card whilst awaiting responses
			 *
			 * XXX: We cannot handle requests while the other interfaces are engaged
			 */
			if (!tiny) {
				ccid_XfrBlock((struct PC_to_RDR_XfrBlock *) request);
			}

			break;

		default:
			debugLog(0, "", "CCID: Unknown message.");
			break;
	}
}

/*
 * Dummy implementation of RDR_to_PC_IccPowerOn
 */
void ccid_IccPowerOn(const CCID_HEADER *request) {
	static struct RDR_to_PC_DataBlock response = {
		.bMessageType = RDR_to_PC_DataBlock,

		.dwLength = 2,
		.abData = { 0x3B, 0x00 }
	};

	response.bSlot = request->bSlot;
	response.bSeq = request->bSeq;

	ccid_tx((CCID_HEADER *) &response);
}

/*
 * Dummy implementation of RDR_to_PC_GetSlotStatus
 */
void ccid_GetSlotStatus(const CCID_HEADER *request) {
	static struct RDR_to_PC_SlotStatus response = {
		.bMessageType = RDR_to_PC_SlotStatus,
	};

	response.bSlot = request->bSlot;
	response.bSeq = request->bSeq;

	ccid_tx((CCID_HEADER *) &response);
}

void ccid_XfrBlock(const struct PC_to_RDR_XfrBlock *request) {
	static CCID_APPLICATION application = NONE;

	struct RDR_to_PC_DataBlock response = {
		.bMessageType = RDR_to_PC_DataBlock,
		.bSlot = request->bSlot,
		.bSeq = request->bSeq,
	};

	const APDU_HEADER *APDU = (APDU_HEADER *) request->abData;

	switch (APDU->INS) {
	case APDU_SELECT_FILE:
		if (memcmp(APDU->data, OPENPGP_APPLICATION_ID, sizeof(OPENPGP_APPLICATION_ID)) == 0) {
			application = CCID_OPENPGP;
			APDU_SW(&response, APDU_SUCCESS);
		} else {
			debugLog(0, "",  "APDU: File not found.");
			APDU_SW(&response, APDU_FILE_NOT_FOUND);
		}

		break;
	default:
		// Call application specific code
		switch (application) {
		case CCID_OPENPGP:
			ccid_OpenPGP(APDU, request->dwLength, &response);
			break;

		default:
			debugLog(0, "",  "APDU: No file selected.");
			APDU_SW(&response, APDU_NOT_SUPPORTED);
			break;
		}

		break;
	}

	ccid_tx((CCID_HEADER *) &response);
}
