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


CCID_HANDLER_INIT(IccPowerOn);
CCID_HANDLER_INIT(GetSlotStatus);

void ccid_read(struct ccid_header *header, const uint8_t *buf) {
	switch (header->bMessageType) {
	CCID_HANDLER_TEST(IccPowerOn);

	case PC_to_RDR_IccPowerOff_Type:
		debugLog(0, "", "PC_to_RDR_IccPowerOff");
	CCID_HANDLER_TEST(GetSlotStatus);

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
