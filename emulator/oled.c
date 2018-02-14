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

#include "oled.h"

#if HEADLESS

void oledInit(void) {}
void oledRefresh(void) {}
void emulatorPoll(void) {}

#else

#include <SDL.h>

#ifdef PIZERO
#include "oled_drivers.h"
static uint8_t oled_type = 0;
#endif

static SDL_Surface *surface = NULL;
static SDL_Surface *video_surface = NULL;
static SDL_Rect dstrect;

static int scale_factor = 1;

void oledInit(void) {
	if (getenv("TREZOR_SDL_SCALE")) {
		scale_factor = atoi(getenv("TREZOR_SDL_SCALE"));
	}

	if (scale_factor < 1 || scale_factor > 10) {
		scale_factor = 1;
	}

	if (SDL_Init(SDL_INIT_VIDEO) != 0) {
		fprintf(stderr, "Failed to initialize SDL: %s\n", SDL_GetError());
		exit(1);
	}
	atexit(SDL_Quit);

	int width = OLED_WIDTH * scale_factor;
	int height = OLED_HEIGHT * scale_factor;

#ifndef PIZERO
	video_surface = SDL_SetVideoMode(width, height, 0, SDL_SWSURFACE);
	if (video_surface == NULL) {
		fprintf(stderr, "Failed to set video mode SDL: %s\n", SDL_GetError());
		exit(1);
	}
	SDL_WM_SetCaption("TREZOR", NULL);
	dstrect.x = 0;
	dstrect.y = 0;
#else
	//output on hdmi via sdl and fb
	const SDL_VideoInfo *vInfo = SDL_GetVideoInfo();
	int res_x = vInfo->current_w;
	int res_y = vInfo->current_h;
	int depth = vInfo->vfmt->BitsPerPixel;

	video_surface = SDL_SetVideoMode(res_x, res_y, depth, SDL_SWSURFACE);
	if (video_surface == NULL) {
		fprintf(stderr, "Failed to set video mode SDL: %s\n", SDL_GetError());
		exit(1);
	}
	dstrect.x = (res_x - width) / 2;
	dstrect.y = (res_y - height) / 2;

	//output on oled if configured also
	if (getenv("TREZOR_OLED_TYPE")) {
		oled_type = atoi(getenv("TREZOR_OLED_TYPE"));

		if (oled_type > 0 && oled_type < OLED_LAST_OLED) {
			oled_init_i2c(oled_type);
		}
	}
#endif

	dstrect.w = width;
	dstrect.h = height;

	SDL_ShowCursor(SDL_DISABLE);

	surface = SDL_CreateRGBSurface(SDL_SWSURFACE, width, height, 16, 0xF800, 0x07E0, 0x001F, 0);
	if (video_surface == NULL) {
		fprintf(stderr, "Failed to create rgb surface SDL: %s\n", SDL_GetError());
		exit(1);
	}

	oledClear();
	oledRefresh();
}

void oledRefresh(void) {
	/* Draw triangle in upper right corner */
	oledInvertDebugLink();

	const uint8_t *buffer = oledGetBuffer();

	int sx, sy;

	for (size_t i = 0; i < OLED_BUFSIZE; i++) {
		int x = (OLED_BUFSIZE - 1 - i) % OLED_WIDTH;
		int y = (OLED_BUFSIZE - 1 - i) / OLED_WIDTH * 8 + 7;

		for (uint8_t shift = 0; shift < 8; shift++, y--) {
			bool set = (buffer[i] >> shift) & 1;

			for (sy = 0; sy < scale_factor; sy++) {
				for (sx = 0; sx < scale_factor; sx++) {
					*(uint16_t *) ((uint8_t *)
						       surface->pixels + 2 * (scale_factor * x + sy) + (scale_factor * y + sx) * surface->pitch) = set ? 0xFFFF : 0;
				}
			}
		}
	}

	SDL_BlitSurface(surface, NULL, video_surface, &dstrect);
	SDL_Flip(video_surface);

	/* Return it back */
	oledInvertDebugLink();

#ifdef PIZERO
	if (oled_type > 0 && oled_type < OLED_LAST_OLED) {
		oled_display(buffer);
	}
#endif
}

void emulatorPoll(void) {
	SDL_Event event;

	while (SDL_PollEvent(&event) > 0) {
		switch (event.type) {
			case SDL_KEYDOWN:
				if (event.key.keysym.sym == SDLK_ESCAPE) {
					exit(1);
				}
				break;
			case SDL_QUIT:
				exit(1);
				break;
		}
	}

}

#endif
