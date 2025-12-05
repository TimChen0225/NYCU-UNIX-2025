
obj-m     += cryptomod.o
ccflags-y += -DEXPORT_SYMTAB

all: 
	make -C ../dist/modulebuild M=$(PWD) modules

clean:
	rm -f rootfs.cpio.bz2
	make -C ../dist/modulebuild M=$(PWD) clean

install: all
	mkdir -p ../rootfs/modules
	cp cryptomod.ko ../rootfs/modules
	(cd ../rootfs && find . | cpio -o -H newc | bzip2) > rootfs.cpio.bz2
	cp rootfs.cpio.bz2 ../dist