CONFIG_MODULE_SIG=n

obj-m = shadow_box.o 
shadow_box-objs := mmu.o iommu.o shadow_watcher.o light_box.o asm.o 

KVERSION = $(shell uname -r)

# List of supported kernel version
#KVERSION = 4.4.0-21-generic
#KVERSION = 4.4.0-31-generic
#KVERSION = 4.8.0-41-generic
#KVERSION = 4.8.0-58-generic
#KVERSION = 4.10.0-28-generic

%.o: %.asm
	nasm -f elf64 -o $@ $^

all: 
	python make_symtable.py
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules 
	mv shadow_box.ko gatekeeper.ko

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean

