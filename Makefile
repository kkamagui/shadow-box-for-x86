CONFIG_MODULE_SIG=n

obj-m = shadow_box.o 
shadow_box-objs := mmu.o iommu.o shadow_watcher.o light_box.o asm.o 

KVERSION = $(shell uname -r)

%.o: %.asm
	nasm -f elf64 -o $@ $^

all: 
	python make_symtable.py
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules 

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean

