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


#include "apdu.h"

const struct APDU_ICC_DO_EXTENDED_CAPS APDU_PGP_EXTENDED_CAPS = {
	.capabilities = {
		.secureMessaging = false,
		.challenge = false,
		.keyImport = false,
		.mutablePWStatus = false,
		.privateUse = false,
		.mutableAlgorithmAttrs = false,
		.AES = false,
		.RFU = 0x0
	},

	.secureMessagingAlgorithm = 0x00,
	.maxChallengeLength = 0x0000,
	.maxCertLength = 0x0000,
	.maxSpecialDOLength = 0x0000,
	.pinBlock2 = false,
	.RFU = 0x0,

	.status = { APDU_SUCCESS }
};

const struct APDU_ICC_DO_PW_STATUS APDU_PGP_PW_STATUS = {
	.validity = 0x01,

	.PW1 = {
		.length = PGP_PW1_LENGTH,
		.type = 0x0
	},
	.RC = 0,
	.PW3 = { 0, 0x0 },
	.counter = { 3, 0, 0 },

	.status = { APDU_SUCCESS }
};
