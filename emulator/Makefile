EMULATOR := 1

OBJS += setup.o

OBJS += buttons.o
OBJS += flash.o
OBJS += oled.o
OBJS += rng.o
OBJS += timer.o
OBJS += strl.o

ifdef PIZERO
OBJS += oled_drivers.o
endif

ifeq ($(TRANSPORT), PIPE)
OBJS += usb.o
else
ifeq ($(TRANSPORT), USBG)
OBJS += usb.o
else
OBJS += udp.o
endif
endif

libemulator.a: $(OBJS)
	$(AR) rcs $@ $(OBJS)

include ../Makefile.include
