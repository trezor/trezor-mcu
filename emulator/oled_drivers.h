/*
 * Copyright (C) 2018 Yannick Heneault <yheneaul@gmail.com>
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
#ifndef __OLED_DRIVERS_H__
#define __OLED_DRIVERS_H__

#include <stdint.h>
#include <stdbool.h>

// Oled supported display
#define OLED_ADAFRUIT_I2C_128x64  1
#define OLED_SEEED_I2C_128x64     2
#define OLED_SH1106_I2C_128x64    3
#define OLED_LAST_OLED            4

bool oled_init_i2c(uint8_t OLED_TYPE);
void oled_display(const uint8_t * p);

#endif
