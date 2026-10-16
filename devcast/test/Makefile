PREFIX ?= /opt/toolchains/dc/sh-elf/bin/sh-elf-
CFLAGS = -ml -m4-single-only -O2 -ffunction-sections -fdata-sections -ffreestanding -fno-builtin

trace-test.elf: start.o test.o test.ld
	$(PREFIX)ld -T test.ld -Map=trace-test.map -o $@ start.o test.o

%.o: %.S
	$(PREFIX)gcc $(CFLAGS) -c -o $@ $<

%.o: %.c
	$(PREFIX)gcc $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o trace-test.elf trace-test.map

.PHONY: clean
