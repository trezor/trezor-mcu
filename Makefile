# Keep intermediate files around
.SECONDARY:

# Configuration (application and library paths) {{{
APPLICATION  ?= firmware

GENERATED       := gen
SUPPORT_LIBRARY := vendor/libopencm3

SUPPORT_LIBRARY_STATIC := $(SUPPORT_LIBRARY)/lib/libopencm3_stm32f2.a

QRENC_LIBRARY   := vendor/trezor-qrenc
CRYPTO_LIBRARY  := vendor/trezor-crypto
# }}}

# Toolchain (ar, cc, ld, objcopy, objdump, git, trezorctl) {{{
CROSS_COMPILE ?= arm-none-eabi-

AR      = $(CROSS_COMPILE)ar
CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)gcc
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump

GIT     = git
TREZORCTL = trezorctl
# }}}

# Compilation configuration (CFLAGS, LDFLAGS) {{{
ARFLAGS  = rcsD --target=arm-none-eabi

CFLAGS   = -O3 -DNDEBUG
override CFLAGS  += -std=gnu99 \
                    -Wall -Wextra -Werror \
                    -Wundef -Wshadow \
                    -Wpointer-arith \
                    -Wformat=2 \
                    -fno-common -fno-exceptions \
                    -fvisibility=internal \
                    -ffunction-sections -fdata-sections \
                    -fstack-protector-all \
                    -mcpu=cortex-m3 -mthumb -msoft-float -DSTM32F2 \
                    -DSCM_REVISION='"$(shell $(GIT) rev-parse HEAD | sed 's/../\\x&/g')"' \
                    -I. -I$(GENERATED) -I$(SUPPORT_LIBRARY)/include \
                    -I$(CRYPTO_LIBRARY) -I$(CRYPTO_LIBRARY)/ed25519-donna \
                    -I$(QRENC_LIBRARY)

override LDFLAGS += -static \
                     -L. -L$(SUPPORT_LIBRARY)/lib -ltrezor -lopencm3_stm32f2 \
                     -Wl,--start-group \
                     -lc -lgcc -lnosys \
                     -Wl,--end-group \
                     -nostartfiles \
                     -Wl,--gc-sections \
                     -march=armv7 -mthumb -mfix-cortex-m3-ldrd -msoft-float
# }}}

# Default target (firmware.bin) {{{
.PHONY: all
all: $(APPLICATION)/firmware.bin
# }}}

# Firmware applications (bootloader, firmware, demo) {{{
APPLICATIONS := bootloader firmware demo

.PHONY: $(APPLICATIONS)
$(APPLICATIONS):
	@$(MAKE) APPLICATION=$@

define add-algorithms
$(eval OBJECTS += $(patsubst %,$(CRYPTO_LIBRARY)/%.o,$(1)))
endef

include $(APPLICATION)/Makefile.include
# }}}

# Pretty compilation output {{{
PRETTY ?= $(shell tty -s || echo 0)
ifeq ($(PRETTY),0)

define pretty_cmd
$(CMD)
endef

else

override CFLAGS  += -fdiagnostics-color
override LDFLAGS += -fdiagnostics-color

TERM_BLACK   := $(shell tput setaf 0)
TERM_RED     := $(shell tput setaf 1)
TERM_GREEN   := $(shell tput setaf 2)
TERM_YELLOW  := $(shell tput setaf 3)
TERM_BLUE    := $(shell tput setaf 4)
TERM_MAGENTA := $(shell tput setaf 5)

TERM_BOLD  := $(shell tput bold)
TERM_DARK  := $(TERM_BOLD)$(TERM_BLACK)
TERM_RESET := $(shell tput sgr0)

define pretty_cmd
+@ \
  OUTPUT="$$($(CMD) 2>&1)"; \
  EXIT_STATUS=$$?; \
  if [ "$$EXIT_STATUS" -ne 0 ]; then \
    STATUS='$(TERM_RED)[FAIL]'; \
  elif [ -z "$(3)" ] && [ -n "$$OUTPUT" ]; then \
    STATUS='$(TERM_YELLOW)[WARN]'; \
  else \
    STATUS='$(TERM_GREEN)[PASS]'; \
  fi; \
  printf '$(TERM_BOLD)$(2)%-6s$(TERM_RESET)$(TERM_BOLD)%-45s$(TERM_RESET)$(TERM_BOLD)%s$(TERM_RESET)\n' '$(1)' '$@' "$$STATUS"; \
  if [ -n "$$OUTPUT" ]; then printf "$(TERM_DARK)>> $(TERM_RESET)$(CMD)\n"; echo "$$OUTPUT"; exit $$EXIT_STATUS; fi
endef

endif
# }}}

# Linker script selection {{{
ifdef APPLICATION_VERSION
override CFLAGS  += -DAPPVER=$(APPLICATION_VERSION)
override LDFLAGS += -Tmemory_app_$(APPLICATION_VERSION).ld
else
override LDFLAGS += -Tmemory.ld
endif
# }}}

# TREZOR firmware library (libtrezor.a) {{{
TREZOR_LIBRARY := libtrezor.a
TREZOR_OBJECTS := buttons.o layout.o oled.o rng.o serialno.o setup.o util.o memory.o \
	$(GENERATED)/bitmaps.o $(GENERATED)/fonts.o
$(TREZOR_LIBRARY): CMD = $(AR) $(ARFLAGS) $@ $^
$(TREZOR_LIBRARY): $(TREZOR_OBJECTS)
	$(call pretty_cmd,LIB,$(TERM_RED))
# }}}

# Dependency generation inclusion (*.d) {{{
-include $(OBJECTS:.o=.d)
-include $(TREZOR_OBJECTS:.o=.d)
# }}}

# Utility recipes (clean, submodules, flash) {{{
.PHONY: clean submodules flash

clean:
	@$(GIT) clean -Xfd
	@$(GIT) submodule foreach $(GIT) clean -Xfd

submodules:
	@$(GIT) submodule update --init

flash: $(APPLICATION)/firmware.bin
	@$(TREZORCTL) firmware_update -f $<
# }}}

# Compilation recipes {{{
%.o: CMD = $(CC) $(CFLAGS) -MMD -c $< -o $@
%.o: %.c
	$(call pretty_cmd,CC,$(TERM_BLUE))

$(APPLICATION)/firmware.bin: CMD = bootloader/firmware_sign.py -f $@
$(APPLICATION)/firmware.bin: $(APPLICATION)/trezor.bin
	@cp $< $@
	$(call pretty_cmd,SIGN,$(TERM_YELLOW),true)

%.bin: CMD = $(OBJCOPY) -O binary $< $@
%.bin: %.elf
	$(call pretty_cmd,BIN,$(TERM_DARK))

$(APPLICATION)/trezor.elf: CMD = $(LD) -o $@ $^ $(LDFLAGS)
$(APPLICATION)/trezor.elf: $(OBJECTS) | $(TREZOR_LIBRARY) $(SUPPORT_LIBRARY_STATIC)
	$(call pretty_cmd,LINK,$(TERM_MAGENTA))

$(SUPPORT_LIBRARY_STATIC): CMD = \
	$(MAKE) -s -C $(SUPPORT_LIBRARY) include/libopencm3/stm32/f2/irq.json.genhdr >/dev/null && \
	$(MAKE) -s -C $(SUPPORT_LIBRARY)/lib/stm32/f2 ARFLAGS='$(ARFLAGS)' SRCLIBDIR='$(abspath $(SUPPORT_LIBRARY)/lib)'
$(SUPPORT_LIBRARY_STATIC): FORCE
	$(call pretty_cmd,LIB,$(TERM_RED),true)

.PHONY: FORCE
FORCE: ;
# }}}

# vim: fdm=marker
