KDIR ?= $(shell realpath $(PWD)/../..)

kbuild:
	$(MAKE) -C $(KDIR) M=$$PWD

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean

.PHONY: clean
