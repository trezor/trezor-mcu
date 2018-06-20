/*
 * This file is part of the TREZOR project, https://trezor.io/
 *
 * Copyright (C) 2017 Saleem Rashid <trezor@saleemrashid.com>
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

#include <stdint.h>

#include "usb.h"

#include "messages.h"
#include "timer.h"
#include "debug.h"

void usbInit(void) {
	emulatorSocketInit();
}

#if DEBUG_LINK
#define _ISDBG (iface == 1)
#else
#define _ISDBG (false)
#endif

void usbPoll(bool tiny) {
	emulatorPoll();

	static uint8_t buffer[64];

	int iface = 0;
	if (emulatorSocketRead(&iface, buffer, sizeof(buffer)) > 0) {
		enum msg_type type;
		if (!tiny) {
			type = _ISDBG ? MSG_TYPE_DEBUG : MSG_TYPE_NORMAL;
		} else {
			type = _ISDBG ? MSG_TYPE_DEBUG_TINY : MSG_TYPE_TINY;
		}

		msg_read_common(type, buffer, sizeof(buffer));
	}

	const uint8_t *data = msg_out_data();
	if (data != NULL) {
		emulatorSocketWrite(0, data, 64);
	}

#if DEBUG_LINK
	data = msg_debug_out_data();
	if (data != NULL) {
		emulatorSocketWrite(1, data, 64);
	}
#endif
}

void usbSleep(uint32_t millis) {
	uint32_t start = timer_ms();

	while ((timer_ms() - start) < millis) {
		usbPoll(true);
	}
}
