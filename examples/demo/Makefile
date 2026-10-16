# Sh4Fit layout demo. `make` links with the KOS-like demo.ld; `make
# LAYOUT=path/to/layout-01.ld` relinks the same objects with a generated script.
# `make LTO=1` builds with link-time optimization, as KallistiOS's environ.sh
# does, keeping the LTO partitions (-save-temps) that the map names.
PREFIX ?= /opt/toolchains/dc/sh-elf/bin/sh-elf-
CFLAGS = -ml -m4-single-only -O2 -ffunction-sections -fdata-sections -ffreestanding -fno-builtin
LINKFLAGS =
ifdef LTO
CFLAGS += -flto -ffat-lto-objects
LINKFLAGS += -O2 -flto -ffunction-sections -fdata-sections -save-temps
endif
OBJS = start.o main.o physics.o menu.o ai.o loader.o render.o audio.o
LAYOUT ?= demo.ld
ELF ?= demo.elf

$(ELF): $(OBJS) $(LAYOUT)
	$(PREFIX)gcc -ml -m4-single-only -nostartfiles -nostdlib -Wl,--gc-sections -T $(LAYOUT) $(LINKFLAGS) \
		-Wl,-Map=$(ELF:.elf=.map) -o $@ $(OBJS) -lgcc

%.o: %.S
	$(PREFIX)gcc $(CFLAGS) -c -o $@ $<

%.o: %.c demo.h
	$(PREFIX)gcc $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o *.elf *.map *.ltrans* *.lto_wrapper_args *.res *.wpa.args.*

.PHONY: clean
