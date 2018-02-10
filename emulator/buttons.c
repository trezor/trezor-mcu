/*
 * This file is part of the TREZOR project, https://trezor.io/
 *
 * Copyright (C) 2017 Saleem Rashid <trezor@saleemrashid.com>
 * Modified Copyright (C) 2018 Yannick Heneault <yheneaul@gmail.com>
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

#include "buttons.h"

#if !HEADLESS
#include <SDL.h>
#endif

#ifdef PIZERO
#include <bcm2835.h>
#endif

uint16_t buttonRead(void) {
	uint16_t state = 0;

#ifdef PIZERO
	state |= bcm2835_gpio_lev(RPI_V2_GPIO_P1_32) == 0 ? BTN_PIN_NO : 0;
	state |= bcm2835_gpio_lev(RPI_V2_GPIO_P1_36) == 0 ? BTN_PIN_YES : 0;
#else

#if !HEADLESS
	const uint8_t *scancodes = SDL_GetKeyState(NULL);
	if (scancodes[SDLK_LEFT]) {
		state |= BTN_PIN_NO;
	}
	if (scancodes[SDLK_RIGHT]) {
		state |= BTN_PIN_YES;
	}
#endif

#endif

	return ~state;
}
