#!/usr/bin/env python
from __future__ import print_function

from collections import OrderedDict

from messages_pb2 import MessageType

from messages_pb2 import wire_in, wire_out
from messages_pb2 import wire_debug_in, wire_debug_out
from messages_pb2 import wire_bootloader, wire_tiny, wire_no_fsm


MESSAGE_TYPES = MessageType.DESCRIPTOR.values
MESSAGE_TYPE_PREFIX = "{}_".format(MessageType.DESCRIPTOR.name)

EXTENSIONS = frozenset({
    wire_bootloader, wire_tiny, wire_no_fsm,
    wire_in, wire_out,
    wire_debug_in, wire_debug_out,
})

EXTENSIONS_MAP = {
    frozenset({wire_in}):                  "MESSAGES_MAP_IN",
    frozenset({wire_out}):                 "MESSAGES_MAP_OUT",
    frozenset({wire_debug_in}):            "MESSAGES_MAP_DEBUG_IN",
    frozenset({wire_debug_out}):           "MESSAGES_MAP_DEBUG_OUT",
    frozenset({wire_tiny, wire_in}):       "MESSAGES_MAP_TINY",
    frozenset({wire_tiny, wire_debug_in}): "MESSAGES_MAP_DEBUG_TINY",
}

EXTENSIONS_SKIP = (
    lambda s, t: wire_bootloader in s,
    lambda s, t: wire_no_fsm in s and wire_tiny not in t,
)

HEADER = """
// This file is automatically generated -- DO NOT EDIT!

#ifndef __MESSAGES_MAP_H__
#define __MESSAGES_MAP_H__
""".lstrip()

FOOTER = """
#endif
""".strip()


def remove_prefix(s, prefix):
    assert s.startswith(prefix)
    return s[len(prefix):]


def filter_extensions(descriptor, iterable):
    extensions = descriptor.GetOptions().Extensions

    return frozenset(filter(lambda item: extensions[item], iterable))


def map_extensions():
    d = OrderedDict((v, []) for v in EXTENSIONS_MAP.values())

    for descriptor in MESSAGE_TYPES:
        k = filter_extensions(descriptor, EXTENSIONS)

        for s, v in EXTENSIONS_MAP.items():
            if not k.issuperset(s):
                continue

            skipped = any(f(k, s) for f in EXTENSIONS_SKIP)
            if skipped:
                continue

            d[v].append(descriptor)

    return d


def print_item(*args):
    print("\tX({}) \\".format(", ".join(args)))


def handle_message(message_type):
    if message_type.GetOptions().deprecated:
        return

    msg_id = MESSAGE_TYPE_PREFIX + message_type.name
    name = remove_prefix(message_type.name, MESSAGE_TYPE_PREFIX)
    fields = "{}_fields".format(name)

    print_item(name, msg_id, fields)


def handle_messages(name, message_types):
    print("#define {}(X) \\".format(name))

    for message_type in message_types:
        handle_message(message_type)

    print()


if __name__ == "__main__":
    print(HEADER)

    for name, message_types in map_extensions().items():
        handle_messages(name, message_types)

    print(FOOTER)
