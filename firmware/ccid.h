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

#ifndef __CCID_H__
#define __CCID_H__

#include "apdu.h"
#include <stdint.h>

#define USB_CLASS_CSCID 0x0b


// CCID command handling macros
#define CCID_HANDLER(type, request, buf)  \
	void PC_to_RDR_ ## type(struct PC_to_RDR_ ## type *request, const uint8_t *buf)

#define CCID_HANDLER_INIT(type)  CCID_HANDLER(type, /* */, /* */)

#define CCID_HANDLER_TEST(type)  \
	case PC_to_RDR_ ## type ## _Type:  \
		PC_to_RDR_ ## type((struct PC_to_RDR_ ## type *) header, buf);  \
		break

#define CCID_CAST_RESPONSE(type)  \
	struct RDR_to_PC_ ## type *response = (struct RDR_to_PC_ ## type *) request;  \
	*response = (struct RDR_to_PC_ ## type) {  \
		.bMessageType = RDR_to_PC_ ## type ## _Type,  \
		.bSlot = request->bSlot,  \
		.bSeq = request->bSeq  \
	}

#define CCID_TX(response)  ccid_tx((response), sizeof(struct ccid_header) + (response)->dwLength)


struct usb_ccid_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint16_t bcdCCID;
	uint8_t  bMaxSlotIndex;
	uint8_t  bVoltageSupport;
	uint32_t dwProtocols;
	uint32_t dwDefaultClock;
	uint32_t dwMaximumClock;
	uint8_t  bNumClockSupported;
	uint32_t dwDataRate;
	uint32_t dwMaxDataRate;
	uint8_t  bNumDataRatesSupported;
	uint32_t dwMaxIFSD;
	uint32_t dwSynchProtocols;
	uint32_t dwMechanical;
	uint32_t dwFeatures;
	uint32_t dwMaxCCIDMessageLength;
	uint8_t  bClassGetResponse;
	uint8_t  bClassEnvelope;
	uint16_t wLcdLayout;
	uint8_t  bPINSupport;
	uint8_t  bMaxCCIDBusySlots;
} __attribute__((packed));

struct ccid_header {
	uint8_t  bMessageType;
	uint32_t dwLength;
	uint8_t  bSlot;
	uint8_t  bSeq;
	uint8_t  reserved[3];
} __attribute__((packed));

struct ccid_slot_status {
	unsigned int bmICCStatus     : 2;
	unsigned int bmRFU           : 4;
	unsigned int bmCommandStatus : 2;
} __attribute__((packed));

void ccid_read(struct ccid_header *header, const uint8_t *buf);

#define PC_to_RDR_IccPowerOn_Type 0x62
struct PC_to_RDR_IccPowerOn {
	uint8_t  bMessageType;
	uint32_t dwLength;
	uint8_t  bSlot;
	uint8_t  bSeq;
	uint8_t  bPowerSelect;
	uint8_t  abRFU[2];
} __attribute__((packed));

#define PC_to_RDR_IccPowerOff_Type 0x63
#define PC_to_RDR_GetSlotStatus_Type 0x65
struct PC_to_RDR_GetSlotStatus {
	uint8_t  bMessageType;
	uint32_t dwLength;
	uint8_t  bSlot;
	uint8_t  bSeq;
	uint8_t  abRFU[3];
} __attribute__((packed));

#define RDR_to_PC_DataBlock_Type 0x80
struct RDR_to_PC_DataBlock {
	uint8_t  bMessageType;
	uint32_t dwLength;
	uint8_t  bSlot;
	uint8_t  bSeq;
	struct ccid_slot_status bStatus;
	uint8_t  bError;
	uint8_t  bChainParameter;
	uint8_t  abData[33];
} __attribute__((packed));

#define RDR_to_PC_SlotStatus_Type 0x81
struct RDR_to_PC_SlotStatus {
	uint8_t  bMessageType;
	uint32_t dwLength;
	uint8_t  bSlot;
	uint8_t  bSeq;
	struct ccid_slot_status bStatus;
	uint8_t  bError;
	uint8_t  bClockStatus;
} __attribute__((packed));

#endif
