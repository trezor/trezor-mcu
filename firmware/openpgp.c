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

#include "crypto.h"
#include "curves.h"
#include "debug.h"
#include "fsm.h"
#include "layout2.h"
#include "macros.h"
#include "nist256p1.h"
#include "pinmatrix.h"
#include "protect.h"
#include "storage.h"
#include "util.h"

typedef OpenPGPMessage_message_t OpenPGPPayload;

static void OpenPGP_GET_DATA(uint16_t TAG, struct RDR_to_PC_DataBlock *response);
static void OpenPGP_PUT_DATA(uint16_t TAG, const uint8_t *data, struct RDR_to_PC_DataBlock *response);
static void OpenPGP_VERIFY(const uint8_t *data, uint8_t length, struct RDR_to_PC_DataBlock *response);
static void OpenPGP_GENERATE_ASYMMETRIC_KEY_PAIR(uint8_t type, struct RDR_to_PC_DataBlock *response);
static void OpenPGP_COMPUTE_DIGITAL_SIGNATURE(const uint8_t *digest, struct RDR_to_PC_DataBlock *response);

static int openpgp_derive_nodes(void);
static const HDNode *openpgp_derive_root_node(void);
static int openpgp_derive_nodes_slip13(void);

static const HDNode *NODE;
static HDNode NODE_SIG, NODE_DEC, NODE_AUT;

// Packets
void *openpgp_append_tag(OpenPGPPayload *message, uint8_t tag, uint32_t length);
uint16_t openpgp_mpi(const uint8_t *data, uint16_t length);

// High-level packet mutation
OPENPGP_NISTP256_PACKET *openpgp_append_public_key(OpenPGPPayload *message, const HDNode *node, uint32_t timestamp, const char *user_id);
void openpgp_append_user_id(OpenPGPPayload *message, const char *user_id, const HDNode *node, const OPENPGP_NISTP256_PACKET *public_key);

// Signature packets
OPENPGP_SIGNATURE_HEADER *openpgp_start_signature(OpenPGPPayload *signature, SHA256_CTX *context, const OPENPGP_NISTP256_PACKET *public_key);
void openpgp_start_unhashed(OpenPGPPayload *signature, OPENPGP_SIGNATURE_HEADER *header);
void openpgp_subpacket(OpenPGPPayload *signature, uint8_t type, const uint8_t *data, uint32_t length);
void openpgp_end_unhashed(OpenPGPPayload *signature, OPENPGP_SIGNATURE_HEADER *header, const OPENPGP_NISTP256_PACKET *public_key);
void openpgp_end_signature(OpenPGPPayload *message, OpenPGPPayload *signature, SHA256_CTX *context, OPENPGP_SIGNATURE_HEADER *header, const HDNode *node);

// Key material
void openpgp_nistp256_packet(OPENPGP_NISTP256_PACKET *packet, const HDNode *node, uint32_t timestamp);
void openpgp_fingerprint(const HDNode *node, uint8_t fingerprint[OPENPGP_FINGERPRINT_LENGTH], uint32_t timestamp, const OPENPGP_NISTP256_PACKET *cached);

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
	if (protectUnlocked(true) && openpgp_derive_nodes() == -1) {
		APDU_SW(response, APDU_UNRECOVERABLE);
		return;
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

	case OPENPGP_PERFORM_SECURITY_OPERATION:
		if (TAG == 0x9E9A) { // COMPUTE DIGITAL SIGNATURE
			// SHA256 is 256-bit
			if ((length - sizeof(*APDU)) != 32) {
				debugLog(0, "", "APDU: DSI not SHA256?");

				// TODO: We should probably be able to handle other algorithms
				APDU_SW(response, APDU_PARAM_DATA_INCORRECT);
			}

			OpenPGP_COMPUTE_DIGITAL_SIGNATURE(APDU->data, response);
		} else {
			debugLog(0, "", "APDU: Unknown PSO");
			APDU_SW(response, APDU_NOT_SUPPORTED);
		}
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
		openpgp_fingerprint(&NODE_SIG, fingerprint, storage.openpgp_timestamp, NULL);
		APDU_WRITE(response, fingerprint, sizeof(fingerprint));
		// Confidentiality
		openpgp_fingerprint(&NODE_DEC, fingerprint, storage.openpgp_timestamp, NULL);
		APDU_WRITE(response, fingerprint, sizeof(fingerprint));
		// Authentication
		openpgp_fingerprint(&NODE_AUT, fingerprint, storage.openpgp_timestamp, NULL);
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
		layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm", NULL, "Do you really want to", "set the name to", (const char *) data, NULL, NULL, NULL);
		if (!ccidProtectButton(false, (CCID_HEADER *) response)) {
			APDU_SW(response, APDU_SECURITY_COND_FAIL);
			layoutHome();
			return;
		}

		storage_setName((const char *) data);
		storage_commit();

		APDU_SW(response, APDU_SUCCESS);
		layoutHome();
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
		// Handle PIN Failures Delay
		uint32_t *fails = ccidPinWait((CCID_HEADER *) response);

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
			storage_resetPinFails(fails);
			if (passphrase) {
				session_cachePassphrase(passphrase);
			}
			APDU_SW(response, APDU_SUCCESS);
		} else {
			storage_increasePinFails(fails);
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

static void OpenPGP_COMPUTE_DIGITAL_SIGNATURE(const uint8_t *digest, struct RDR_to_PC_DataBlock *response) {
	if (!protectUnlocked(true)) {
		APDU_SW(response, APDU_SECURITY_COND_FAIL);
		return;
	}

	layoutDialogSwipe(&bmp_icon_question, "Cancel", "Confirm", NULL, "Do you really want to", "compute an OpenPGP", "signature?", NULL, NULL, NULL);
	if (!ccidProtectButton(false, (CCID_HEADER *) response)) {
		APDU_SW(response, APDU_SECURITY_COND_FAIL);
		layoutHome();
		return;
	}

	static uint8_t signature[64];

	// TODO: Ed25519 support
	if (ecdsa_sign_digest(&nist256p1, NODE_SIG.private_key, digest, signature, NULL, NULL) != 0) {
		debugLog(0, "", "PSO: Signing failed");
		APDU_SW(response, APDU_UNRECOVERABLE);
	}

	APDU_WRITE(response, signature, sizeof(signature));
	APDU_SW(response, APDU_SUCCESS);
	layoutHome();
}

int openpgp_derive_nodes(void) {
	if (!storage.has_openpgp_derivation || !storage.has_openpgp_curve_name || !storage.has_openpgp_timestamp)
		// OpenPGP not initialized yet
		return -1;

	if (!protectUnlocked(true))
		// PIN or passphrase required
		return -1;

	if (storage.openpgp_derivation == OpenPGPDerivationType_OpenPGPDerivation_Simple) {
		NODE = openpgp_derive_root_node();

		if (NODE == NULL) {
			return -1;
		}

		// Initialize specific keys
		NODE_SIG = *NODE; // Digital Signature
		hdnode_private_ckd(&NODE_SIG, OPENPGP_BIP32_INDEX_SIG);
		NODE_DEC = *NODE; // Confidentiality
		hdnode_private_ckd(&NODE_DEC, OPENPGP_BIP32_INDEX_DEC);
		NODE_AUT = *NODE; // Authentication
		hdnode_private_ckd(&NODE_AUT, OPENPGP_BIP32_INDEX_AUT);

		return 0;
	} else if (storage.openpgp_derivation == OpenPGPDerivationType_OpenPGPDerivation_SLIP13) {
		return openpgp_derive_nodes_slip13();
	} else {
		// Should not reach here
		return -1;
	}
}

// https://github.com/romanz/trezor-agent/blob/master/trezor_agent/gpg/client.py
int openpgp_derive_nodes_slip13() {
	// "gpg://First Last <user@domain.tld>"
	IdentityType identity = {
		.has_index = true,
		.index = 0,

		.has_proto = true,
		.proto = "gpg",

		.has_host = true,
	};
	strlcpy(identity.host, storage.openpgp_user_id, sizeof(identity.host));

	uint8_t hash[32];
	if (!cryptoIdentityFingerprint(&identity, hash)) {
		return -1;
	}

	uint32_t address_n[5];
	address_n[0] = 0x80000000 | 13;
	address_n[1] = 0x80000000 | hash[ 0] | (hash[ 1] << 8) | (hash[ 2] << 16) | (hash[ 3] << 24);
	address_n[2] = 0x80000000 | hash[ 4] | (hash[ 5] << 8) | (hash[ 6] << 16) | (hash[ 7] << 24);
	address_n[3] = 0x80000000 | hash[ 8] | (hash[ 9] << 8) | (hash[10] << 16) | (hash[11] << 24);
	address_n[4] = 0x80000000 | hash[12] | (hash[13] << 8) | (hash[14] << 16) | (hash[15] << 24);

	static const uint32_t address_n_count = sizeof(address_n) / sizeof(uint32_t);

	static HDNode node;
	if (!storage_getRootNode(&node, storage.openpgp_curve_name, true))
		// Failed to derive root node
		return -1;

	NODE_SIG = node;
	if (!hdnode_private_ckd_cached(&NODE_SIG, address_n, address_n_count, NULL)) {
		return -1;
	}

	// TODO: Use a different key?
	NODE_AUT = NODE_SIG;

	address_n[0] = 0x80000000 | 17; // ECDH
	NODE_DEC = node;
	if (!hdnode_private_ckd_cached(&NODE_DEC, address_n, address_n_count, NULL)) {
		return -1;
	}

	return 0;
}

// Used for simple derivation
const HDNode *openpgp_derive_root_node() {
	static HDNode node;
	static uint32_t address_n[] = { OPENPGP_DERIVATION_PATH, 0 };
	static const uint8_t address_n_count = sizeof(address_n) / sizeof(uint32_t);

	if (!storage_getRootNode(&node, storage.openpgp_curve_name, true))
		// Failed to derive root node
		return NULL;

	address_n[address_n_count - 1] = 0x80000000 | storage.openpgp_timestamp;
	if (!hdnode_private_ckd_cached(&node, address_n, address_n_count, NULL))
		// Failed to derive node
		return NULL;

	return &node;
}

void openpgp_construct_pubkey(OpenPGPMessage *response, const char *user_id) {
	// Initialize NODE, NODE_*
	if (openpgp_derive_nodes() == -1)
		fsm_sendFailure(FailureType_Failure_Other, "Failed to derive OpenPGP nodes");

	response->has_message = true;
	OpenPGPPayload *message = &response->message;

	OPENPGP_NISTP256_PACKET *public_key = openpgp_append_public_key(message,
		&NODE_SIG, storage.openpgp_timestamp, user_id);

	(void) public_key;
}

OPENPGP_NISTP256_PACKET *openpgp_append_public_key(OpenPGPPayload *message, const HDNode *node, uint32_t timestamp, const char *user_id) {
	// TODO: Ed25519 support
	OPENPGP_NISTP256_PACKET *packet = openpgp_append_tag(message,
			6, // Public-Key Packet
			sizeof(OPENPGP_NISTP256_PACKET));

	openpgp_nistp256_packet(packet, node, timestamp);

	openpgp_append_user_id(message, user_id, node, packet);

	return packet;
}

uint16_t openpgp_mpi(const uint8_t *data, uint16_t length) {
	// Performance is more important than memory
	static const uint8_t lookup_table[] = {
		0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, // 0x00 - 0x0f
		5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, // 0x10 - 0x1f
		6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, // 0x20 - 0x2f
		6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, // 0x30 - 0x3f
		7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, // 0x40 - 0x4f
		7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, // 0x50 - 0x5f
		7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, // 0x60 - 0x6f
		7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, // 0x70 - 0x7f
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, // 0x80 - 0x8f
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, // 0x90 - 0x9f
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, // 0xa0 - 0xaf
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, // 0xb0 - 0xbf
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, // 0xc0 - 0xcf
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, // 0xd0 - 0xdf
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, // 0xe0 - 0xef
		8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, // 0xf0 - 0xff
	};

	return lookup_table[*data] + ((length - 1) << 3);
}

void *openpgp_append_tag(OpenPGPPayload *message, uint8_t tag, uint32_t length) {
	message->bytes[message->size++] = 0b11000000 | tag;

	if (length < 192) {
		message->bytes[message->size++] = length;
	} else if (length < 8384) {
		message->bytes[message->size++] = (length >> 8) + 191;
		message->bytes[message->size++] = (length & 0xFF) + 0x40;
	} else {
		message->bytes[message->size++] = 255;
		message->bytes[message->size++] = (length & 0xFF000000) >> 24;
		message->bytes[message->size++] = (length & 0x00FF0000) >> 16;
		message->bytes[message->size++] = (length & 0x0000FF00) >>  8;
		message->bytes[message->size++] = (length & 0xFF0000FF);
	}

	void *data = &message->bytes[message->size];
	message->size += length;
	return data;
}

void openpgp_append_user_id(OpenPGPPayload *message, const char *user_id, const HDNode *node, const OPENPGP_NISTP256_PACKET *public_key) {
	uint32_t length = strlen(user_id);

	char *packet = openpgp_append_tag(message,
			13, // User ID Packet
			length);

	// Avoid null termination
	strncpy(packet, user_id, length);

	static OpenPGPPayload signature;
	signature.size = 0;

	static SHA256_CTX context;

	OPENPGP_SIGNATURE_HEADER *header = openpgp_start_signature(&signature, &context, public_key);
	header->type = 0x13; // Positive certification of a User ID and Public-Key packet

	uint8_t body_header[] = {
		0xB4, // User ID certification
		(length & 0xFF000000) >> 24,
		(length & 0x00FF0000) >> 16,
		(length & 0x0000FF00) >>  8,
		(length & 0x000000FF),
	};
	sha256_Update(&context, body_header, sizeof(body_header));
	sha256_Update(&context, (uint8_t *) user_id, length);

	// Hashed subpackets

	openpgp_subpacket(&signature,
		2, // Signature Creation Time
		(uint8_t *) &public_key->timestamp,
		sizeof(public_key->timestamp));

	openpgp_subpacket(&signature,
		27, // Key Flags
		& (uint8_t) { 0x01 | 0x02 }, // [SC]
		sizeof(uint8_t));

	openpgp_subpacket(&signature,
		11, // Preferred Symmetric Algorithms
		& (uint8_t) { 9 }, // AES-256
		sizeof(uint8_t));

	openpgp_subpacket(&signature,
		21, // Preferred Hash Algorithms
		& (uint8_t) { OPENPGP_SHA256_ID },
		sizeof(uint8_t));

	openpgp_subpacket(&signature,
		22, // Preferred Compression Algorithms
		& (uint8_t) { 0 }, // Uncompressed
		sizeof(uint8_t));

	openpgp_subpacket(&signature,
		30, // Features
		& (uint8_t) { 0x01 }, // Modification detection
		sizeof(uint8_t));

	openpgp_subpacket(&signature,
		23, // Key Server Preferences
		& (uint8_t) { 0x80 }, // No-modify
		sizeof(uint8_t));

	openpgp_start_unhashed(&signature, header);

	// Unhashed subpackets

	openpgp_end_unhashed(&signature, header, public_key);

	openpgp_end_signature(message, &signature, &context, header, node);
}

OPENPGP_SIGNATURE_HEADER *openpgp_start_signature(OpenPGPPayload *signature, SHA256_CTX *context, const OPENPGP_NISTP256_PACKET *public_key) {
	sha256_Init(context);

	OPENPGP_SIGNATURE_HEADER *header = (OPENPGP_SIGNATURE_HEADER *) &signature->bytes[signature->size];
	*header = OPENPGP_SIGNATURE_HEADER_DEFAULT;
	signature->size += sizeof(*header);

	static uint8_t public_header[] = { 0x99, sizeof(*public_key) >> 8, sizeof(*public_key) & 0xFF };
	sha256_Update(context, public_header, sizeof(public_header));
	sha256_Update(context, (uint8_t *) public_key, sizeof(*public_key));

	return header;
}

void openpgp_start_unhashed(OpenPGPPayload *signature, OPENPGP_SIGNATURE_HEADER *header) {
	uint8_t *start = (uint8_t *) header;
	header->hashed_count = &signature->bytes[signature->size] - &start[sizeof(*header)];

	// Reserve unhashed count
	signature->size += 2;
}

void openpgp_subpacket(OpenPGPPayload *signature, uint8_t type, const uint8_t *data, uint32_t length) {
	// Length should include type octet
	uint32_t subpacket_length = length + 1;

	// Length
	if (subpacket_length < 192) {
		signature->bytes[signature->size++] = subpacket_length;
	} else if (subpacket_length < 8384) {
		signature->bytes[signature->size++] = (subpacket_length >> 8) + 191;
		signature->bytes[signature->size++] = (subpacket_length & 0xFF) + 0x40;
	} else {
		signature->bytes[signature->size++] = 255;
		signature->bytes[signature->size++] = (subpacket_length & 0xFF000000) >> 24;
		signature->bytes[signature->size++] = (subpacket_length & 0x00FF0000) >> 16;
		signature->bytes[signature->size++] = (subpacket_length & 0x0000FF00) >>  8;
		signature->bytes[signature->size++] = (subpacket_length & 0xFF0000FF);
	}

	// Type
	signature->bytes[signature->size++] = type;

	// Data
	memcpy(&signature->bytes[signature->size], data, length);
	signature->size += length;
}

void openpgp_end_unhashed(OpenPGPPayload *signature, OPENPGP_SIGNATURE_HEADER *header, const OPENPGP_NISTP256_PACKET *public_key) {
	if (public_key != NULL) {
		static uint8_t fingerprint[OPENPGP_FINGERPRINT_LENGTH];
		openpgp_fingerprint(NULL, fingerprint, 0, public_key);

		openpgp_subpacket(signature,
			16, // Issuer
			&fingerprint[OPENPGP_FINGERPRINT_LENGTH - 8],
			8);
	}

	// Calculate length
	uint8_t *start = (uint8_t *) header;
	uint8_t *length = &start[sizeof(*header) + header->hashed_count];

	uint16_t native_length = &signature->bytes[signature->size] - &length[2];
	length[0] = native_length >> 8;
	length[1] = native_length & 0xFF;
}

void openpgp_end_signature(OpenPGPPayload *message, OpenPGPPayload *signature, SHA256_CTX *context, OPENPGP_SIGNATURE_HEADER *header, const HDNode *node) {
	uint8_t *start = (uint8_t *) header;

	// Fix up endianess
	uint16_t hashed_count = header->hashed_count;
	header->hashed_count = htons(hashed_count);

	sha256_Update(context, start, sizeof(*header)); // Signature header
	sha256_Update(context, start + sizeof(*header), hashed_count); // Hashed subpackets

	uint32_t hashed_length = sizeof(*header) + hashed_count;
	uint8_t trailer[] = {
		0x04, // Version number
		0xFF,
		(hashed_length & 0xFF000000) >> 24,
		(hashed_length & 0x00FF0000) >> 16,
		(hashed_length & 0x0000FF00) >>  8,
		(hashed_length & 0x000000FF),
	};
	sha256_Update(context, trailer, sizeof(trailer));

	static uint8_t digest[32];
	sha256_Final(context, digest);

	// Left most 16-bits of hash value
	signature->bytes[signature->size++] = digest[0];
	signature->bytes[signature->size++] = digest[1];

	// Error checking?
	static uint8_t signature_data[64];
	ecdsa_sign_digest(&nist256p1, node->private_key, digest, signature_data, NULL, NULL);

	// First signature parameter
	uint16_t mpi = openpgp_mpi(signature_data, 32);
	signature->bytes[signature->size++] = mpi >> 8;
	signature->bytes[signature->size++] = mpi & 0xFF;
	memcpy(&signature->bytes[signature->size], signature_data, 32);
	signature->size += 32;

	// Second signature parameter
	mpi = openpgp_mpi(&signature_data[32], 32);
	signature->bytes[signature->size++] = mpi >> 8;
	signature->bytes[signature->size++] = mpi & 0xFF;
	memcpy(&signature->bytes[signature->size], &signature_data[32], 32);
	signature->size += 32;

	uint32_t length = &signature->bytes[signature->size] - start;
	void *dest = openpgp_append_tag(message,
		2, // Signature Packet
		length);

	// Actually copy entire signature to final payload
	memcpy(dest, start, length);
}

void openpgp_nistp256_packet(OPENPGP_NISTP256_PACKET *packet, const HDNode *node, uint32_t timestamp) {
	*packet = OPENPGP_NISTP256_PACKET_DEFAULT;

	packet->timestamp = htonl(timestamp);
	memcpy(packet->curve_oid, &OPENPGP_NISTP256[1], sizeof(packet->curve_oid));
	ecdsa_get_public_key65(node->curve->params, node->private_key, packet->mpi);
};

// TODO: Ed25519 support
void openpgp_fingerprint(const HDNode *node, uint8_t *fingerprint, const uint32_t timestamp, const OPENPGP_NISTP256_PACKET *cached) {
	static SHA1_CTX context;
	static OPENPGP_NISTP256_PACKET packet;
	static uint8_t header[] = { 0x99, sizeof(packet) >> 8, sizeof(packet) & 0xFF };

	sha1_Init(&context);

	sha1_Update(&context, header, sizeof(header));

	if (cached == NULL) {
		openpgp_nistp256_packet(&packet, node, timestamp);
		sha1_Update(&context, (uint8_t *) &packet, sizeof(packet));
	} else {
		sha1_Update(&context, (uint8_t *) cached, sizeof(*cached));
	}

	sha1_Final(&context, fingerprint);
}
