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

#include "trezor.h"
#include "oled.h"
#include "bitmaps.h"
#include "util.h"
#include "usb.h"
#include "setup.h"
#include "storage.h"
#include "layout.h"
#include "layout2.h"
#include "rng.h"

#ifdef FASTFLASH
#include "buttons.h"

extern uint8_t _RAM_FASTFLASH_START;

extern uint8_t _FASTFLASH_BLOB_START;
extern uint8_t _FASTFLASH_BLOB_SIZE;
// extern uint8_t _FASTFLASH_BLOB_END;

static uint32_t RAM_FASTFLASH_START  = (uint32_t) &_RAM_FASTFLASH_START;

static uint8_t *FASTFLASH_BLOB_START = &_FASTFLASH_BLOB_START;
static uint32_t FASTFLASH_BLOB_SIZE  = (uint32_t) &_FASTFLASH_BLOB_SIZE;

static inline void __attribute__((noreturn)) load_bootloader(void)
{
	// load bootloader into RAM to prevent overwriting itself
	memcpy((uint8_t *) RAM_FASTFLASH_START, FASTFLASH_BLOB_START, FASTFLASH_BLOB_SIZE);

	// jump to bootloader
	load_address(RAM_FASTFLASH_START);
}
#endif

uint32_t __stack_chk_guard;

void __attribute__((noreturn)) __stack_chk_fail(void)
{
	layoutDialog(&bmp_icon_error, NULL, NULL, NULL, "Stack smashing", "detected.", NULL, "Please unplug", "the device.", NULL);
	for (;;) {} // loop forever
}

int main(void)
{
	__stack_chk_guard = random32();
#ifndef APPVER
	setup();
	oledInit();
#else
	setupApp();
#endif

#ifdef FASTFLASH
	uint16_t state = gpio_port_read(BTN_PORT);
	if ((state & BTN_PIN_NO) == 0) {
		load_bootloader();
	}
#endif

#if DEBUG_LINK
	oledSetDebug(1);
	storage_reset(); // wipe storage if debug link
	storage_reset_uuid();
	storage_commit();
	storage_clearPinArea(); // reset PIN failures if debug link
#endif

	oledDrawBitmap(40, 0, &bmp_logo64);
	oledRefresh();

	storage_init();
	layoutHome();
	usbInit();
	for (;;) {
		usbPoll();
	}

	return 0;
}
