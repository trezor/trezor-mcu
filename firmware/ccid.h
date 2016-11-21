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

#include <stdint.h>

typedef struct {
	uint8_t  bMessageType;
	uint32_t dwLength;
	uint8_t  bSlot;
	uint8_t  bSeq;
	uint8_t  abRFU[3];
	uint8_t  abData[];
} __attribute__((packed)) CCID_HEADER;

void ccid_rx(const CCID_HEADER *request, char tiny);

/*
 * USB CCID Descriptor
 */
#define USB_CLASS_CSCID 0x0b
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

/*
 * CCID Messages
 */

enum {
	PC_to_RDR_IccPowerOn    = 0x62,
	PC_to_RDR_IccPowerOff   = 0x63,
	PC_to_RDR_GetSlotStatus = 0x65,
	PC_to_RDR_XfrBlock      = 0x6F,

	RDR_to_PC_DataBlock     = 0x80,
	RDR_to_PC_SlotStatus    = 0x81,
};

struct PC_to_RDR_IccPowerOn {
	uint8_t  bMessageType;
	uint32_t dwLength;
	uint8_t  bSlot;
	uint8_t  bSeq;
	uint8_t  bPowerSelect;
	uint8_t  abRFU[2];
} __attribute__((packed));

struct PC_to_RDR_GetSlotStatus {
	uint8_t  bMessageType;
	uint32_t dwLength;
	uint8_t  bSlot;
	uint8_t  bSeq;
	uint8_t  abRFU[3];
} __attribute__((packed));

struct PC_to_RDR_XfrBlock {
	uint8_t  bMessageType;
	uint32_t dwLength;
	uint8_t  bSlot;
	uint8_t  bSeq;
	uint8_t  bBWI;
	uint16_t wLevelParameter;
	uint8_t  abData[];
} __attribute__((packed));

struct RDR_to_PC_DataBlock {
	uint8_t  bMessageType;
	uint32_t dwLength;
	uint8_t  bSlot;
	uint8_t  bSeq;
	unsigned bmICCStatus     : 2;
	unsigned bmRFU           : 4;
	unsigned bmCommandStatus : 2;
	uint8_t  bError;
	uint8_t  bChainParameter;
	uint8_t  abData[261];
} __attribute__((packed));

struct RDR_to_PC_SlotStatus {
	uint8_t  bMessageType;
	uint32_t dwLength;
	uint8_t  bSlot;
	uint8_t  bSeq;
	unsigned bmICCStatus     : 2;
	unsigned bmRFU           : 4;
	unsigned bmCommandStatus : 2;
	uint8_t  bError;
	uint8_t  bClockStatus;
} __attribute__((packed));

#endif
