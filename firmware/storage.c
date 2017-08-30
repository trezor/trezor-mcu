/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
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

#include <string.h>
#include <stdint.h>

#include "messages.pb.h"
#include "storage.pb.h"

#include "trezor.h"
#include "sha2.h"
#include "aes.h"
#include "pbkdf2.h"
#include "bip32.h"
#include "bip39.h"
#include "curves.h"
#include "util.h"
#include "rng.h"
#include "storage.h"
#include "debug.h"
#include "protect.h"
#include "layout2.h"
#include "usb.h"
#include "gettext.h"

Storage CONFIDENTIAL storage;

uint32_t storage_uuid[12/sizeof(uint32_t)];
char    storage_uuid_str[25];

static bool sessionSeedCached, sessionSeedUsesPassphrase;

static uint8_t CONFIDENTIAL sessionSeed[64];

static bool sessionPinCached;

static bool sessionPassphraseCached;
static char CONFIDENTIAL sessionPassphrase[51];

void storage_show_error(void)
{
	layoutDialog(&bmp_icon_error, NULL, NULL, NULL, _("Storage failure"), _("detected."), NULL, _("Please unplug"), _("the device."), NULL);
	system_halt();
}

void storage_init(void)
{
	if (!storage_from_flash()) {
		storage_reset();
		storage_reset_uuid();
		storage_commit();
		storage_clearPinArea();
	}
}

void storage_reset_uuid(void)
{
	// set random uuid
	random_buffer((uint8_t *)storage_uuid, sizeof(storage_uuid));
	data2hex(storage_uuid, sizeof(storage_uuid), storage_uuid_str);
}

void storage_reset(void)
{
	// reset storage struct
	memset(&storage, 0, sizeof(storage));
	storage.version = STORAGE_VERSION;
	session_clear(true); // clear PIN as well
}

void session_clear(bool clear_pin)
{
	sessionSeedCached = false;
	memset(&sessionSeed, 0, sizeof(sessionSeed));
	sessionPassphraseCached = false;
	memset(&sessionPassphrase, 0, sizeof(sessionPassphrase));
	if (clear_pin) {
		sessionPinCached = false;
	}
}

void storage_loadDevice(LoadDevice *msg)
{
	storage_reset();

	storage.has_imported = true;
	storage.imported = true;

	if (msg->has_pin > 0) {
		storage_setPin(msg->pin);
	}

	if (msg->has_passphrase_protection) {
		storage.has_passphrase_protection = true;
		storage.passphrase_protection = msg->passphrase_protection;
	} else {
		storage.has_passphrase_protection = false;
	}

	if (msg->has_node) {
		storage.has_node = true;
		storage.has_mnemonic = false;
		memcpy(&storage.node, &(msg->node), sizeof(HDNodeType));
		sessionSeedCached = false;
		memset(&sessionSeed, 0, sizeof(sessionSeed));
	} else if (msg->has_mnemonic) {
		storage.has_mnemonic = true;
		storage.has_node = false;
		strlcpy(storage.mnemonic, msg->mnemonic, sizeof(storage.mnemonic));
		sessionSeedCached = false;
		memset(&sessionSeed, 0, sizeof(sessionSeed));
	}

	if (msg->has_language) {
		storage_setLanguage(msg->language);
	}

	if (msg->has_label) {
		storage_setLabel(msg->label);
	}

	if (msg->has_u2f_counter) {
		storage_setU2FCounter(msg->u2f_counter);
	}
}

void storage_setLabel(const char *label)
{
	if (!label) return;
	storage.has_label = true;
	strlcpy(storage.label, label, sizeof(storage.label));
}

void storage_setLanguage(const char *lang)
{
	if (!lang) return;
	// sanity check
	if (strcmp(lang, "english") == 0) {
		storage.has_language = true;
		strlcpy(storage.language, lang, sizeof(storage.language));
	}
}

void storage_setPassphraseProtection(bool passphrase_protection)
{
	sessionSeedCached = false;
	sessionPassphraseCached = false;

	storage.has_passphrase_protection = true;
	storage.passphrase_protection = passphrase_protection;
}

void storage_setHomescreen(const uint8_t *data, uint32_t size)
{
	if (data && size == 1024) {
		storage.has_homescreen = true;
		memcpy(storage.homescreen.bytes, data, size);
		storage.homescreen.size = size;
	} else {
		storage.has_homescreen = false;
		memset(storage.homescreen.bytes, 0, sizeof(storage.homescreen.bytes));
		storage.homescreen.size = 0;
	}
}

void get_root_node_callback(uint32_t iter, uint32_t total)
{
	usbSleep(1);
	layoutProgress(_("Waking up"), 1000 * iter / total);
}

const uint8_t *storage_getSeed(bool usePassphrase)
{
	// root node is properly cached
	if (usePassphrase == sessionSeedUsesPassphrase
		&& sessionSeedCached) {
		return sessionSeed;
	}

	// if storage has mnemonic, convert it to node and use it
	if (storage.has_mnemonic) {
		if (usePassphrase && !protectPassphrase()) {
			return NULL;
		}
		// if storage was not imported (i.e. it was properly generated or recovered)
		if (!storage.has_imported || !storage.imported) {
			// test whether mnemonic is a valid BIP-0039 mnemonic
			if (!mnemonic_check(storage.mnemonic)) {
				// and if not then halt the device
				storage_show_error();
			}
		}
		char oldTiny = usbTiny(1);
		mnemonic_to_seed(storage.mnemonic, usePassphrase ? sessionPassphrase : "", sessionSeed, get_root_node_callback); // BIP-0039
		usbTiny(oldTiny);
		sessionSeedCached = true;
		sessionSeedUsesPassphrase = usePassphrase;
		return sessionSeed;
	}

	return NULL;
}

bool storage_getRootNode(HDNode *node, const char *curve, bool usePassphrase)
{
	// if storage has node, decrypt and use it
	if (storage.has_node && strcmp(curve, SECP256K1_NAME) == 0) {
		if (!protectPassphrase()) {
			return false;
		}
		if (hdnode_from_xprv(storage.node.depth, storage.node.child_num, storage.node.chain_code.bytes, storage.node.private_key.bytes, curve, node) == 0) {
			return false;
		}
		if (storage.has_passphrase_protection && storage.passphrase_protection && sessionPassphraseCached && strlen(sessionPassphrase) > 0) {
			// decrypt hd node
			uint8_t secret[64];
			PBKDF2_HMAC_SHA512_CTX pctx;
			pbkdf2_hmac_sha512_Init(&pctx, (const uint8_t *)sessionPassphrase, strlen(sessionPassphrase), (const uint8_t *)"TREZORHD", 8);
			get_root_node_callback(0, BIP39_PBKDF2_ROUNDS);
			for (int i = 0; i < 8; i++) {
				pbkdf2_hmac_sha512_Update(&pctx, BIP39_PBKDF2_ROUNDS / 8);
				get_root_node_callback((i + 1) * BIP39_PBKDF2_ROUNDS / 8, BIP39_PBKDF2_ROUNDS);
			}
			pbkdf2_hmac_sha512_Final(&pctx, secret);
			aes_decrypt_ctx ctx;
			aes_decrypt_key256(secret, &ctx);
			aes_cbc_decrypt(node->chain_code, node->chain_code, 32, secret + 32, &ctx);
			aes_cbc_decrypt(node->private_key, node->private_key, 32, secret + 32, &ctx);
		}
		return true;
	}

	const uint8_t *seed = storage_getSeed(usePassphrase);
	if (seed == NULL) {
		return false;
	}
	
	return hdnode_from_seed(seed, 64, curve, node);
}

const char *storage_getLabel(void)
{
	return storage.has_label ? storage.label : 0;
}

const char *storage_getLanguage(void)
{
	return storage.has_language ? storage.language : 0;
}

const uint8_t *storage_getHomescreen(void)
{
	return (storage.has_homescreen && storage.homescreen.size == 1024) ? storage.homescreen.bytes : 0;
}

/* Check whether mnemonic matches storage. The mnemonic must be
 * a null-terminated string.
 */
bool storage_containsMnemonic(const char *mnemonic) {
	/* The execution time of the following code only depends on the
	 * (public) input.  This avoids timing attacks.
	 */
	char diff = 0;
	uint32_t i = 0;
	for (; mnemonic[i]; i++) {
		diff |= (storage.mnemonic[i] - mnemonic[i]);
	}
	diff |= storage.mnemonic[i];
	return diff == 0;
}

/* Check whether pin matches storage.  The pin must be
 * a null-terminated string with at most 9 characters.
 */
bool storage_containsPin(const char *pin)
{
	/* The execution time of the following code only depends on the
	 * (public) input.  This avoids timing attacks.
	 */
	char diff = 0;
	uint32_t i = 0;
	while (pin[i]) {
		diff |= storage.pin[i] - pin[i];
		i++;
	}
	diff |= storage.pin[i];
	return diff == 0;
}

bool storage_hasPin(void)
{
	return storage.has_pin && storage.pin[0] != 0;
}

void storage_setPin(const char *pin)
{
	if (pin && pin[0]) {
		storage.has_pin = true;
		strlcpy(storage.pin, pin, sizeof(storage.pin));
	} else {
		storage.has_pin = false;
		storage.pin[0] = 0;
	}
	storage_commit();
	sessionPinCached = false;
}

void session_cachePassphrase(const char *passphrase)
{
	strlcpy(sessionPassphrase, passphrase, sizeof(sessionPassphrase));
	sessionPassphraseCached = true;
}

bool session_isPassphraseCached(void)
{
	return sessionPassphraseCached;
}

void session_cachePin(void)
{
	sessionPinCached = true;
}

bool session_isPinCached(void)
{
	return sessionPinCached;
}

bool storage_isInitialized(void)
{
	return storage.has_node || storage.has_mnemonic;
}

bool storage_needsBackup(void)
{
	return storage.has_needs_backup && storage.needs_backup;
}

void storage_applyFlags(uint32_t flags)
{
	if ((storage.flags | flags) == storage.flags) {
		return; // no new flags
	}
	storage.has_flags = true;
	storage.flags |= flags;
	storage_commit();
}

uint32_t storage_getFlags(void)
{
	return storage.has_flags ? storage.flags : 0;
}

void storage_wipe(void)
{
	storage_reset();
	storage_reset_uuid();
	storage_commit();
	storage_clearPinArea();
}
