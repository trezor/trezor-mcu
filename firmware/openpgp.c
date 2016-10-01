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


#include "openpgp.h"

#include "curves.h"
#include "debug.h"
#include "layout2.h"
#include "macros.h"
#include "pinmatrix.h"
#include "protect.h"
#include "storage.h"
#include "util.h"

static void OpenPGP_GET_DATA(uint16_t TAG, struct RDR_to_PC_DataBlock *response);
static void OpenPGP_PUT_DATA(uint16_t TAG, const uint8_t *data, struct RDR_to_PC_DataBlock *response);

static void OpenPGP_VERIFY(const uint8_t *data, uint8_t length, struct RDR_to_PC_DataBlock *response);

static void OpenPGP_GENERATE_ASYMMETRIC_KEY_PAIR(uint8_t type, struct RDR_to_PC_DataBlock *response);

static const HDNode *openpgp_derive_root_node(void);

static const HDNode *NODE;
static HDNode NODE_SIG, NODE_DEC, NODE_AUT;

void openpgp_fingerprint(const HDNode *node, uint8_t fingerprint[OPENPGP_FINGERPRINT_LENGTH], uint32_t timestamp);

static const OPENPGP_PW_STATUS PW_STATUS = {
	.Validity = 0x1,
	.PW1 = { 0b0110110, 0x0 },
	.PW3 = { 0b0110110, 0x0 },
	.Errors = { 0x03, 0x00, 0x03 },
};

static const OPENPGP_EXTENDED_CAPS EXTENDED_CAPS;

/*
 * Handle all OpenPGP APDUs received
 */
void ccid_OpenPGP(const APDU_HEADER *APDU, const uint8_t length, struct RDR_to_PC_DataBlock *response) {
	if (protectUnlocked(true)) {
		NODE = openpgp_derive_root_node();
		if (NODE == NULL) {
			APDU_SW(response, APDU_UNRECOVERABLE);
			return;
		}

		// Initialize specific keys
		NODE_SIG = *NODE; // Digital Signature
		hdnode_private_ckd(&NODE_SIG, OPENPGP_BIP32_INDEX_SIG);
		NODE_DEC = *NODE; // Confidentiality
		hdnode_private_ckd(&NODE_DEC, OPENPGP_BIP32_INDEX_DEC);
		NODE_AUT = *NODE; // Authentication
		hdnode_private_ckd(&NODE_AUT, OPENPGP_BIP32_INDEX_AUT);
	}

	const uint16_t TAG = APDU->P1 << 8 | APDU->P2;
	switch (APDU->INS) {
	case APDU_GET_DATA:
		OpenPGP_GET_DATA(TAG, response);
		break;

	case APDU_PUT_DATA:
		OpenPGP_PUT_DATA(TAG, APDU->data, response);
		break;

	case APDU_VERIFY:
		OpenPGP_VERIFY(APDU->data, length - sizeof(*APDU), response);
		break;

	case OPENPGP_GENERATE_ASYMMETRIC_KEY_PAIR:
		OpenPGP_GENERATE_ASYMMETRIC_KEY_PAIR(*APDU->data, response);
		break;

	default:
		debugLog(0, "", "APDU: Unknown INS");
		APDU_SW(response, APDU_NOT_SUPPORTED);
		break;
	}
}

/*
 * Handle access to OpenPGP Data Objects
 */
void OpenPGP_GET_DATA(const uint16_t TAG, struct RDR_to_PC_DataBlock *response) {
	static ISO7816_AID OPENPGP_AID = {
		.RID = { 0xD2, 0x76, 0x00, 0x01, 0x24 },
		.Application = 0x01,
		.Version = OPENPGP_VERSION,
		.Manufacturer = OPENPGP_MANUFACTURER,
	};
	memcpy(&OPENPGP_AID.SerialNumber, storage_uuid, sizeof(OPENPGP_AID.SerialNumber));

	const char *name = storage_getName();

	switch (TAG) {
	case 0x004F: // Application identifier (AID), ISO 7816-4
		APDU_WRITE(response, &OPENPGP_AID, sizeof(OPENPGP_AID));
		APDU_SW(response, APDU_SUCCESS);
		break;

	case 0x00C4: // PW status Bytes
		APDU_WRITE(response, &PW_STATUS, sizeof(PW_STATUS));
		APDU_SW(response, APDU_SUCCESS);
		break;

	case 0x0065: // Cardholder Related Data
		if (!protectUnlockedPin(true)) {
			APDU_SW(response, APDU_SECURITY_COND_FAIL);
			break;
		}

		APDU_CONSTRUCT(response, TAG, NULL, 0);

		// Name according to ISO/IEC 7501-1
		APDU_CONSTRUCT(response, 0x005B, name, strlen(name));

		APDU_CONSTRUCT_END(response);
		APDU_SW(response, APDU_SUCCESS);
		break;

	// Algorithm attributes
	case 0x00C1: // Sig
	case 0x00C2: // Dec
	case 0x00C3: // Aut
		/* Oh no! Information leakage! This is necessary because GnuPG only tries
		 * to read the Algorithm Attributes once and defaults to RSA otherwise.
		 * If we withhold the information while the device is locked, GnuPG will
		 * use the default. */
		if (strcmp(storage.openpgp_curve_name, ED25519_NAME) == 0) {
			APDU_WRITE(response, OPENPGP_ED25519, sizeof(OPENPGP_ED25519));
		} else { // NIST256P1_NAME
			APDU_WRITE(response, OPENPGP_NISTP256, sizeof(OPENPGP_NISTP256));
		}

		APDU_SW(response, APDU_SUCCESS);
		break;

	case 0x006E: // Application Related Data
		if (!protectUnlocked(true)) {
			APDU_SW(response, APDU_SECURITY_COND_FAIL);
			break;
		}

		APDU_CONSTRUCT(response, TAG, NULL, 0);

		// Fingerprints
		static uint8_t fingerprint[OPENPGP_FINGERPRINT_LENGTH];
		APDU_CONSTRUCT(response, 0x00C5, NULL, OPENPGP_FINGERPRINT_LENGTH * 3);
		// Digital Signature
		openpgp_fingerprint(&NODE_SIG, fingerprint, storage.openpgp_timestamp);
		APDU_WRITE(response, fingerprint, sizeof(fingerprint));
		// Confidentiality
		openpgp_fingerprint(&NODE_DEC, fingerprint, storage.openpgp_timestamp);
		APDU_WRITE(response, fingerprint, sizeof(fingerprint));
		// Authentication
		openpgp_fingerprint(&NODE_AUT, fingerprint, storage.openpgp_timestamp);
		APDU_WRITE(response, fingerprint, sizeof(fingerprint));

		// List of generation dates/times of public key pairs
		const uint32_t timestamp = htonl(storage.openpgp_timestamp);
		APDU_CONSTRUCT(response, 0x00CD, NULL, sizeof(timestamp) * 3);
		APDU_WRITE(response, &timestamp, sizeof(timestamp)); // Sig
		APDU_WRITE(response, &timestamp, sizeof(timestamp)); // Dec
		APDU_WRITE(response, &timestamp, sizeof(timestamp)); // Aut

		APDU_CONSTRUCT_END(response);
		APDU_SW(response, APDU_SUCCESS);
		break;

	case 0x007A: // Security support template
		if (!protectUnlocked(true)) {
			pinmatrix_start("OpenPGP (see manual)");
		}

		APDU_SW(response, APDU_DATA_NOT_FOUND);
		break;

	case 0x00C0: // Extended capabilities
		/* This is used when the device is locked so we can ensure the client
		 * doesn't cache other responses in the 'Application Related Data'
		 * response but still allow the client to talk with the device */
		APDU_WRITE(response, &EXTENDED_CAPS, sizeof(EXTENDED_CAPS));
		APDU_SW(response, APDU_SUCCESS);
		break;

	default:
		debugLog(0, "", "APDU GET DATA: Referenced data not found");
		APDU_SW(response, APDU_DATA_NOT_FOUND);
		break;
	}
}

/*
 * Handle mutation of OpenPGP Data Objects with the TREZOR security
 */
static void OpenPGP_PUT_DATA(const uint16_t TAG, const uint8_t *data, struct RDR_to_PC_DataBlock *response) {
	if (!protectUnlockedPin(true)) {
		APDU_SW(response, APDU_SECURITY_COND_FAIL);
		return;
	}

	switch (TAG) {
	case 0x005B: // Name according to ISO/IEC 7501-1
		storage_setName((const char *) data);
		storage_commit();

		APDU_SW(response, APDU_SUCCESS);
		break;

	default:
		debugLog(0, "", "APDU PUT DATA: Function not supported");
		APDU_SW(response, APDU_FCN_NOT_SUPPORTED);
		break;
	}
}

static void OpenPGP_VERIFY(const uint8_t *data, const uint8_t length, struct RDR_to_PC_DataBlock *response) {
	/*
	 * Due to the way OpenPGP works, we use a complex system for entering the PIN and passphrase.
	 *
	 * Our OpenPGP password follows the format of
	 * [scrambled TREZOR PIN] + [0s to pad to OpenPGP minimum length] + [' '] + [passphrase]
	 *
	 * All but the scrambled TREZOR PIN are optional, if they are not necessary for the user's configuration.
	 *
	 * Examples:
	 * '123400'       Scrambled PIN of '1234', padded out to PW1 minimum of 6
	 * '123400 PWD'   Scrambled PIN of '1234', passphrase of 'PWD'
	 * '1234   PWD'   Scrambled PIN of '1234', passphrase of '  PWD'
	 */

	if (protectUnlocked(true)) {
		/* Due to the way the TREZOR works, it is:
		 * a) pointless to check subsequent passwords and
		 * b) fallacious, due to the PIN scrambling
		 */

		APDU_SW(response, APDU_SUCCESS);
	} else {
		static char PIN[10];

		uint8_t limit = length;
		const uint8_t *separator;
		const char *passphrase = NULL;

		// Find beginning of passphrase
		if ((separator = memchr(data, ' ', limit - 1))) {
			limit = separator - data;
			passphrase = (char *) separator + 1;
		}

		// Find end of PIN
		if ((separator = memchr(data, '0', limit))) {
			limit = separator - data;
		}

		strlcpy(PIN, (char *) data, min(sizeof(PIN), limit + 1u));

		pinmatrix_done(PIN);
		if (storage_isPinCorrect(PIN)) {
			session_cachePin();
			if (passphrase) {
				session_cachePassphrase(passphrase);
			}
			APDU_SW(response, APDU_SUCCESS);
		} else {
			APDU_SW(response, APDU_SECURITY_COND_FAIL);
		}

		layoutHome();
	}
}

static void OpenPGP_GENERATE_ASYMMETRIC_KEY_PAIR(uint8_t type, struct RDR_to_PC_DataBlock *response) {
	if (!protectUnlocked(true)) {
		APDU_SW(response, APDU_SECURITY_COND_FAIL);
		return;
	}

	const HDNode *node;

	switch (type) {
		case 0xB6: // Digital signature
			node = &NODE_SIG;
			break;

		case 0xB8: // Confidentiality
			node = &NODE_DEC;
			break;

		case 0xA4: // Authentication
			node = &NODE_AUT;
			break;

		default:
			APDU_SW(response, APDU_PARAM_DATA_INCORRECT);
			return;
	}

	static uint8_t buffer[65];

	// TODO: Ed25519 support
	ecdsa_get_public_key65(node->curve->params, node->private_key, buffer);

	APDU_CONSTRUCT(response, 0x7F49, NULL, 0);
	APDU_CONSTRUCT(response, 0x86, buffer, sizeof(buffer));
	APDU_CONSTRUCT_END(response);
	APDU_SW(response, APDU_SUCCESS);
}

const HDNode *openpgp_derive_root_node() {
	static HDNode node;
	static uint32_t address_n[] = { OPENPGP_DERIVATION_PATH, 0 };
	static const uint8_t address_n_count = sizeof(address_n) / sizeof(uint32_t);

	if (!protectUnlocked(true))
		// PIN or passphrase required
		return NULL;

	if (!storage.has_openpgp_curve_name || !storage.has_openpgp_timestamp)
		// OpenPGP not initialized yet
		return NULL;

	if (!storage_getRootNode(&node, storage.openpgp_curve_name, true))
		// Failed to derive root node
		return NULL;

	address_n[address_n_count - 1] = 0x80000000 | storage.openpgp_timestamp;
	if (!hdnode_private_ckd_cached(&node, address_n, address_n_count, NULL))
		// Failed to derive node
		return NULL;

	return &node;
}

// TODO: Ed25519 support
void openpgp_fingerprint(const HDNode *node, uint8_t *fingerprint, const uint32_t timestamp) {
	uint8_t length = 0;
	static uint8_t buffer[65];

	static SHA1_CTX context;
	sha1_Init(&context);

	/* TODO: given a particular curve, Public Key Packet length *should* be
	 * predictable, so we should be able to move packet building into its own
	 * function, using a custom struct for each curve */

	// Version
	buffer[length++] = 0x04;
	// Creation time
	buffer[length++] = timestamp >> 24 & 0xff;
	buffer[length++] = timestamp >> 16 & 0xff;
	buffer[length++] = timestamp >>  8 & 0xff;
	buffer[length++] = timestamp       & 0xff;
	// Public key algorithm
	buffer[length++] = *OPENPGP_NISTP256;
	// Curve OID Length
	buffer[length++] = sizeof(OPENPGP_NISTP256) - 1;

	sha1_Update(&context, buffer, length);
	length = 0;

	// Curve OID
	sha1_Update(&context, &OPENPGP_NISTP256[1], sizeof(OPENPGP_NISTP256) - 1);

	// MPI Length
	const uint16_t mpi_length = 3 + 2 * 32 * 8; // 04 || x || y
	buffer[length++] = mpi_length >> 8;
	buffer[length++] = mpi_length & 0xff;

	sha1_Update(&context, buffer, length);
	length = 0;

	// MPI
	ecdsa_get_public_key65(node->curve->params, node->private_key, buffer);
	sha1_Update(&context, buffer, sizeof(buffer));

	sha1_Final(&context, fingerprint);
}
