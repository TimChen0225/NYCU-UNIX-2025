ROOTFS_DIR=./rootfs
OUTPUT_FILE=../rootfs.cpio.bz2
DIST_DIR=./dist
DIST_FILE=$(DIST_DIR)/rootfs.cpio.bz2

.PHONY: all clean

all:
	@echo "Creating rootfs archive..."
	@cd $(ROOTFS_DIR) && find . | cpio -o -H newc | bzip2 > $(OUTPUT_FILE)
	@echo "Copying rootfs.cpio.bz2 to dist directory..."
	@cp -f $(OUTPUT_FILE) $(DIST_FILE)
	@echo "Done."

clean:
	@rm -f $(OUTPUT_FILE) $(DIST_FILE)
	@echo "Cleaned up generated files."