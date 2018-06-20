/*
 * This file is part of the TREZOR project, https://trezor.io/
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

#ifndef __MESSAGES_H__
#define __MESSAGES_H__

#include <stdint.h>
#include <stdbool.h>
#include "trezor.h"

enum msg_type {
    MSG_TYPE_NORMAL,
    MSG_TYPE_DEBUG,
    MSG_TYPE_TINY,
    MSG_TYPE_DEBUG_TINY,
};

void msg_read_common(enum msg_type type, const uint8_t *buf, uint32_t len);
bool msg_write_common(enum msg_type type, uint16_t msg_id, const void *msg_ptr);

#define MSG_IN_SIZE   (12 * 1024)
#define MSG_OUT_SIZE  (12 * 1024)
#define MSG_TINY_SIZE (128)

const uint8_t *msg_out_data(void);
#define msg_write(msg_id, msg_ptr) msg_write_common(MSG_TYPE_NORMAL, msg_id, msg_ptr)

extern uint8_t msg_tiny[MSG_TINY_SIZE];
uint16_t msg_tiny_get_id(void);

#if DEBUG_LINK

#define MSG_DEBUG_OUT_SIZE (4 * 1024)

const uint8_t *msg_debug_out_data(void);
#define msg_debug_write(msg_id, msg_ptr) msg_write_common(MSG_TYPE_DEBUG, msg_id, msg_ptr)

#endif

#endif
