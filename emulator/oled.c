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

#include "oled.h"

#if HEADLESS

void oledInit(void) {}
void oledRefresh(void) {}
void emulatorPoll(void) {}

#else

#include <SDL.h>

#define ENV_OLED_SCALE "TREZOR_OLED_SCALE"

static SDL_Renderer *renderer = NULL;
static SDL_Texture *texture = NULL;

unsigned long emulatorGetScale(void);

void oledInit(void) {
	if (SDL_Init(SDL_INIT_VIDEO) != 0) {
		fprintf(stderr, "Failed to initialize SDL: %s\n", SDL_GetError());
		exit(1);
	}
	atexit(SDL_Quit);

	unsigned long scale = emulatorGetScale();

	SDL_Window *window = SDL_CreateWindow("TREZOR",
		SDL_WINDOWPOS_UNDEFINED,
		SDL_WINDOWPOS_UNDEFINED,
		OLED_WIDTH * scale,
	        OLED_HEIGHT * scale,
		0);

	if (window == NULL) {
		fprintf(stderr, "Failed to create window: %s\n", SDL_GetError());
		exit(1);
	}

	renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED);
	if (!renderer) {
		fprintf(stderr, "Failed to create renderer: %s\n", SDL_GetError());
		exit(1);
	}

	/* Use unscaled coordinate system */
	SDL_RenderSetLogicalSize(renderer, OLED_WIDTH, OLED_HEIGHT);

	texture = SDL_CreateTexture(renderer, SDL_PIXELFORMAT_ARGB8888, SDL_TEXTUREACCESS_STREAMING, OLED_WIDTH, OLED_HEIGHT);

	oledClear();
	oledRefresh();
}

unsigned long emulatorGetScale(void) {
	unsigned long scale = 1;

	const char *variable = getenv(ENV_OLED_SCALE);
	if (variable != NULL && variable[0] != '\0') {
		char *endptr;
		scale = strtoul(variable, &endptr, 10);
		if (*endptr != '\0') {
			fprintf(stderr, "Failed to convert " ENV_OLED_SCALE "\n");
			exit(1);
		}
	}

	return scale;
}

void oledRefresh(void) {
	/* Draw triangle in upper right corner */
	oledInvertDebugLink();

	const uint8_t *buffer = oledGetBuffer();

	static uint32_t data[OLED_HEIGHT][OLED_WIDTH];

	for (size_t i = 0; i < OLED_BUFSIZE; i++) {
		int x = (OLED_BUFSIZE - 1 - i) % OLED_WIDTH;
		int y = (OLED_BUFSIZE - 1 - i) / OLED_WIDTH * 8 + 7;

		for (uint8_t shift = 0; shift < 8; shift++, y--) {
			bool set = (buffer[i] >> shift) & 1;
			data[y][x] = set ? 0xFFFFFFFF : 0xFF000000;
		}
	}

	SDL_UpdateTexture(texture, NULL, data, OLED_WIDTH * sizeof(uint32_t));
	SDL_RenderCopy(renderer, texture, NULL, NULL);
	SDL_RenderPresent(renderer);

	/* Return it back */
	oledInvertDebugLink();
}

void emulatorPoll(void) {
	SDL_Event event;

	if (SDL_PollEvent(&event)) {
		if (event.type == SDL_QUIT) {
			exit(1);
		}
	}
}

#endif
