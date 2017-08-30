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

#ifndef __FLASH_H__
#define __FLASH_H__

#include <stdbool.h>
#include <stdint.h>

#define STORAGE_VERSION 8

void storage_check_flash_errors(void);

bool storage_from_flash(void);
void storage_commit(void);

void storage_clearPinArea(void);

void storage_resetPinFails(uint32_t *pinfailsptr);
bool storage_increasePinFails(uint32_t *pinfailsptr);
uint32_t *storage_getPinFailsPtr(void);

void storage_setU2FCounter(uint32_t u2fcounter);
uint32_t storage_nextU2FCounter(void);

#endif
