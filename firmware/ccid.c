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
#include "apdu.h"
#include "ccid.h"
#include "debug.h"
#include "layout2.h"
#include "storage.h"
#include "protect.h"
#include "pinmatrix.h"

#include <string.h>

CCID_HANDLER_INIT(IccPowerOn);
CCID_HANDLER_INIT(GetSlotStatus);
CCID_HANDLER_INIT(XfrBlock);

void ccid_read(struct ccid_header *header, uint8_t *buf) {
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

CCID_HANDLER(XfrBlock, request, buf) {
	const struct APDU_REQUEST *apdu = (struct APDU_REQUEST *) buf;
	const uint8_t *data = &buf[sizeof(*apdu)];
	debugLog(0, "", __func__);

	if (apdu->Lc != request->dwLength - sizeof(*apdu)) {
		// Attempted attack?
		debugLog(0, "", "APDU: Invalid Length!");
		return;
	}

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
	response.dwLength = 0;

	static struct APDU_ICC_DO_AID APDU_PGP_AID = {
		.RID = { APDU_PGP_APPLICATION_ID },
		.application = 0x01,
		.version = APDU_PGP_VERSION,
		.manufacturer = APDU_PGP_MANUFACTURER,
		.RFU = { 0x00, 0x00 },

		.status = { APDU_SUCCESS }
	};
	memcpy(&APDU_PGP_AID.serialNumber, storage_uuid, sizeof(APDU_PGP_AID.serialNumber));

	static struct APDU_ICC_DO_FINGERPRINTS APDU_PGP_FINGERPRINTS;

	// Cardholder's name
	const char *name = storage_getName();

	response.bSlot = request->bSlot;
	response.bSeq = request->bSeq;

	uint16_t tag = (apdu->P1 << 8) + apdu->P2;
	if (APDU_CHECK(buf, request->dwLength, APDU_PGP_COMMAND_SELECT)) {
		APDU_RETURN(response, SUCCESS);
	} else if (apdu->INS == APDU_GET_DATA) {
		switch (tag) {
		APDU_DATA_OBJECT(AID);
		APDU_DATA_OBJECT(PW_STATUS);

		case APDU_ICC_DO_NAME_TAG:
			if (name && protectUnlockedPin(true)) {
				strlcpy((char *) response.abData, name, sizeof(response.abData));
				response.dwLength += strlen(name);
			}

			APDU_RETURN(response, SUCCESS);
			break;

		case APDU_ICC_DO_SECURITY_SUPPORT_TEMPL_TAG:
			if (!protectUnlocked(true)) {
				debugLog(0, "", "APDU GET DATA: displaying PIN matrix");
				pinmatrix_start("OpenPGP (see manual)");
			}

			APDU_RETURN(response, NOT_SUPPORTED);
			break;

		APDU_DATA_OBJECT_CONSTRUCT_INIT(APPLICATION_RELATED_DATA)
			APDU_DATA_OBJECT_CONSTRUCT(EXTENDED_CAPS);
			APDU_DATA_OBJECT_CONSTRUCT(FINGERPRINTS);
			APDU_DATA_OBJECT_CONSTRUCT_END();
			APDU_RETURN(response, SUCCESS);
			break;

		default:
			debugLog(0, "", "APDU GET DATA: Referenced data not found");
			APDU_RETURN(response, DATA_NOT_FOUND);
			break;
		}
	} else if (apdu->INS == APDU_PUT_DATA && protectUnlockedPin(true)) {
		switch (tag) {
		case APDU_ICC_DO_NAME_TAG:
			storage_setName((const char *) data);
			storage_commit();
			APDU_RETURN(response, SUCCESS);
			break;
		default:
			debugLog(0, "", "APDU PUT DATA: Function not supported");
			APDU_RETURN(response, FCN_NO_SUPPORT);
			break;
		}
	} else if (apdu->INS == APDU_VERIFY) {
		/*
		 * Due to the way OpenPGP works, we use a complex system for entering the PIN and passphrase.
		 *
		 * Our OpenPGP password follows the format of
		 * [scrambled TREZOR PIN] + [0s to pad to OpenPGP minimum length] + [' '] + [passphrase]
		 *
		 * All but the scrambled TREZOR PIN are optional, if they are not necessary for the user's parameters.
		 *
		 * Examples:
		 * '123400    '   Scrambled PIN of '1234', padded out to PW1 minimum of 6
		 * '123400 PWD'   Scrambled PIN of '1234', passphrase of 'PWD'
		 * '1234   PWD'   Scrambled PIN of '1234', passphrase of '  PWD'
		 */

		if (!protectUnlocked(true)) {
			// Initialize passphrase to point to a '\0' so it acts like a zero-length string
			char *pin = (char *) data, *passphrase = (char *) &data[apdu->Lc], *separator;

			// The buffer containing the request should be uint8_t[65] to allow for a null terminator
			*passphrase = '\0';

			if ((separator = strchr(pin, ' '))) {
				*separator = '\0';
				passphrase = separator + 1;
			}

			if ((separator = strchr(pin, '0'))) {
				*separator = '\0';
			}

			pinmatrix_done(pin);

			if (storage_isPinCorrect(pin)) {
				session_cachePin();
				session_cachePassphrase(passphrase);
				APDU_RETURN(response, SUCCESS);
			} else {
				APDU_RETURN(response, PW_WRONG);
			}

			layoutHome();
		} else {
			/* Due to the way the TREZOR works, it is:
			 * a) pointless to check subsequent passwords and
			 * b) fallacious, due to the PIN scrambling
			 */
			APDU_RETURN(response, SUCCESS);
		}
	} else {
		switch (apdu->INS) {
		case APDU_SELECT_FILE:
			debugLog(0, "", "APDU SELECT FILE: File not found");
			APDU_RETURN(response, FILE_NOT_FOUND);
			break;
		case APDU_PUT_DATA:
			APDU_RETURN(response, PW_WRONG);
			break;
		default:
			debugLog(0, "", "APDU unmatched");
			APDU_RETURN(response, NOT_SUPPORTED);
			break;
		}
	}

	CCID_TX(&response);
}
