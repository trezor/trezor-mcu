OBJS += buttons.o
OBJS += layout.o
OBJS += oled.o
OBJS += rng.o
OBJS += util.o
OBJS += memory.o

ifneq ($(EMULATOR),1)
OBJS += startup.o
OBJS += setup.o
OBJS += timer.o
OBJS += serialno.o
endif

OBJS += gen/bitmaps.o
OBJS += gen/fonts.o

libtrezor.a: $(OBJS)
	$(AR) rcs libtrezor.a $(OBJS)

include Makefile.include

.PHONY: vendor

vendor:
	git submodule update --init
