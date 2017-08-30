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

#include "flash.h"

#include <string.h>

#include <libopencm3/stm32/flash.h>

#include "memory.h"
#include "storage.h"
#include "util.h"

/*
 storage layout:

 offset |  type/length |  description
--------+--------------+-------------------------------
 0x0000 |     4 bytes  |  magic = 'stor'
 0x0004 |    12 bytes  |  uuid
 0x0010 |     ? bytes  |  Storage structure
--------+--------------+-------------------------------
 0x4000 |     4 kbytes |  area for pin failures
 0x5000 |   256 bytes  |  area for u2f counter updates
 0x5100 | 11.75 kbytes |  reserved

The area for pin failures looks like this:
0 ... 0 pinfail 0xffffffff .. 0xffffffff
The pinfail is a binary number of the form 1...10...0,
the number of zeros is the number of pin failures.
This layout is used because we can only clear bits without 
erasing the flash.

The area for u2f counter updates is just a sequence of zero-bits
followed by a sequence of one-bits.  The bits in a byte are numbered
from LSB to MSB.  The number of zero bits is the offset that should
be added to the storage u2f_counter to get the real counter value.

 */

/* Current u2f offset, i.e. u2f counter is
 * storage.u2f_counter + storage_u2f_offset.
 * This corresponds to the number of cleared bits in the U2FAREA.
 */
static uint32_t storage_u2f_offset;

#define FLASH_STORAGE_PINAREA     (FLASH_META_START + 0x4000)
#define FLASH_STORAGE_PINAREA_LEN (0x1000)
#define FLASH_STORAGE_U2FAREA     (FLASH_STORAGE_PINAREA + FLASH_STORAGE_PINAREA_LEN)
#define FLASH_STORAGE_U2FAREA_LEN (0x100)
#define FLASH_STORAGE_REALLEN (4 + sizeof(storage_uuid) + sizeof(Storage))

_Static_assert(FLASH_STORAGE_START + FLASH_STORAGE_REALLEN <= FLASH_STORAGE_PINAREA, "Storage struct is too large for TREZOR flash");
_Static_assert((sizeof(storage_uuid) & 3) == 0, "storage uuid unaligned");
_Static_assert((sizeof(storage) & 3) == 0, "storage unaligned");

/* magic constant to check validity of storage block */
static const uint32_t storage_magic = 0x726f7473;   // 'stor' as uint32_t

void storage_check_flash_errors(void)
{
	// flash operation failed
	if (FLASH_SR & (FLASH_SR_PGAERR | FLASH_SR_PGPERR | FLASH_SR_PGSERR | FLASH_SR_WRPERR)) {
		storage_show_error();
	}
}

bool storage_from_flash(void)
{
	if (memcmp((void *)FLASH_STORAGE_START, &storage_magic, 4) != 0) {
		// wrong magic
		return false;
	}

	uint32_t version = ((Storage *)(FLASH_STORAGE_START + 4 + sizeof(storage_uuid)))->version;
	// version 1: since 1.0.0
	// version 2: since 1.2.1
	// version 3: since 1.3.1
	// version 4: since 1.3.2
	// version 5: since 1.3.3
	// version 6: since 1.3.6
	// version 7: since 1.5.1
	// version 8: since 1.5.2
	if (version > STORAGE_VERSION) {
		// downgrade -> clear storage
		return false;
	}

	// load uuid
	memcpy(storage_uuid, (void *)(FLASH_STORAGE_START + 4), sizeof(storage_uuid));
	data2hex(storage_uuid, sizeof(storage_uuid), storage_uuid_str);

	// copy storage
	size_t old_storage_size = 0;

	if (version == 1 || version == 2) {
		old_storage_size = 460;
	} else
	if (version == 3 || version == 4 || version == 5) {
		old_storage_size = 1488;
	} else
	if (version == 6 || version == 7) {
		old_storage_size = 1496;
	} else
	if (version == 8) {
		old_storage_size = 1504;
	}

	memset(&storage, 0, sizeof(Storage));
	memcpy(&storage, (void *)(FLASH_STORAGE_START + 4 + sizeof(storage_uuid)), old_storage_size);

	if (version <= 5) {
		// convert PIN failure counter from version 5 format
		uint32_t pinctr = storage.has_pin_failed_attempts
			? storage.pin_failed_attempts : 0;
		if (pinctr > 31)
			pinctr = 31;
		flash_clear_status_flags();
		flash_unlock();
		// erase extra storage sector
		flash_erase_sector(FLASH_META_SECTOR_LAST, FLASH_CR_PROGRAM_X32);
		flash_program_word(FLASH_STORAGE_PINAREA, 0xffffffff << pinctr);
		flash_lock();
		storage_check_flash_errors();
		storage.has_pin_failed_attempts = false;
		storage.pin_failed_attempts = 0;
	}
	uint32_t *u2fptr = (uint32_t*) FLASH_STORAGE_U2FAREA;
	while (*u2fptr == 0)
		u2fptr++;
	storage_u2f_offset = 32 * (u2fptr - (uint32_t*) FLASH_STORAGE_U2FAREA);
	uint32_t u2fword = *u2fptr;
	while ((u2fword & 1) == 0) {
		storage_u2f_offset++;
		u2fword >>= 1;
	}
	// upgrade storage version
	if (version != STORAGE_VERSION) {
		storage.version = STORAGE_VERSION;
		storage_commit();
	}
	return true;
}

static uint32_t storage_flash_words(uint32_t addr, uint32_t *src, int nwords) {
	for (int i = 0; i < nwords; i++) {
		flash_program_word(addr, *src++);
		addr += 4;
	}
	return addr;
}

static void storage_commit_locked(void)
{
	uint32_t meta_backup[FLASH_META_DESC_LEN/4];

	// backup meta
	memcpy(meta_backup, (uint8_t*)FLASH_META_START, FLASH_META_DESC_LEN);

	// erase storage
	flash_erase_sector(FLASH_META_SECTOR_FIRST, FLASH_CR_PROGRAM_X32);
	// copy meta
	uint32_t flash = FLASH_META_START;
	flash = storage_flash_words(flash, meta_backup, FLASH_META_DESC_LEN/4);
	// copy storage
	flash_program_word(flash, storage_magic);
	flash += 4;
	flash = storage_flash_words(flash, storage_uuid, sizeof(storage_uuid)/4);
	flash = storage_flash_words(flash, (uint32_t *)&storage, sizeof(storage)/4);
	// fill remainder with zero for future extensions
	while (flash < FLASH_STORAGE_PINAREA) {
		flash_program_word(flash, 0);
		flash += 4;
	}
}

void storage_commit(void)
{
	flash_clear_status_flags();
	flash_unlock();
	storage_commit_locked();
	flash_lock();
	storage_check_flash_errors();
}

void storage_clearPinArea(void)
{
	flash_clear_status_flags();
	flash_unlock();
	flash_erase_sector(FLASH_META_SECTOR_LAST, FLASH_CR_PROGRAM_X32);
	flash_lock();
	storage_check_flash_errors();
	storage_u2f_offset = 0;
}

// called when u2f area or pin area overflows
static void storage_area_recycle(uint32_t new_pinfails)
{
	// first clear storage marker.  In case of a failure below it is better
	// to clear the storage than to allow restarting with zero PIN failures
	flash_program_word(FLASH_STORAGE_START, 0);
	if (*(uint32_t *)FLASH_STORAGE_START != 0) {
		storage_show_error();
	}

	// erase storage sector
	flash_erase_sector(FLASH_META_SECTOR_LAST, FLASH_CR_PROGRAM_X32);
	flash_program_word(FLASH_STORAGE_PINAREA, new_pinfails);
	if (*(uint32_t *)FLASH_STORAGE_PINAREA != new_pinfails) {
		storage_show_error();
	}

	if (storage_u2f_offset > 0) {
		storage.has_u2f_counter = true;
		storage.u2f_counter += storage_u2f_offset;
		storage_u2f_offset = 0;
	}
	storage_commit_locked();
}

void storage_resetPinFails(uint32_t *pinfailsptr)
{
	flash_clear_status_flags();
	flash_unlock();
	if ((uint32_t) (pinfailsptr + 1)
		>= FLASH_STORAGE_PINAREA + FLASH_STORAGE_PINAREA_LEN) {
		// recycle extra storage sector
		storage_area_recycle(0xffffffff);
	} else {
		flash_program_word((uint32_t) pinfailsptr, 0);
	}
	flash_lock();
	storage_check_flash_errors();
}

bool storage_increasePinFails(uint32_t *pinfailsptr)
{
	uint32_t newctr = *pinfailsptr << 1;
	// counter already at maximum, we do not increase it any more
	// return success so that a good pin is accepted
	if (!newctr)
		return true;

	flash_clear_status_flags();
	flash_unlock();
	flash_program_word((uint32_t) pinfailsptr, newctr);
	flash_lock();
	storage_check_flash_errors();

	return *pinfailsptr == newctr;
}

uint32_t *storage_getPinFailsPtr(void)
{
	uint32_t *pinfailsptr = (uint32_t *) FLASH_STORAGE_PINAREA;
	while (*pinfailsptr == 0)
		pinfailsptr++;
	return pinfailsptr;
}

void storage_setU2FCounter(uint32_t u2fcounter)
{
	storage.has_u2f_counter = true;
	storage.u2f_counter = u2fcounter - storage_u2f_offset;
	storage_commit();
}

uint32_t storage_nextU2FCounter(void)
{
	uint32_t *ptr = ((uint32_t *) FLASH_STORAGE_U2FAREA) + (storage_u2f_offset / 32);
	uint32_t newval = 0xfffffffe << (storage_u2f_offset & 31);

	flash_clear_status_flags();
	flash_unlock();
	flash_program_word((uint32_t) ptr, newval);
	storage_u2f_offset++;
	if (storage_u2f_offset >= 8 * FLASH_STORAGE_U2FAREA_LEN) {
		storage_area_recycle(*storage_getPinFailsPtr());
	}
	flash_lock();
	storage_check_flash_errors();
	return storage.u2f_counter + storage_u2f_offset;
}
