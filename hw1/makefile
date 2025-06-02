# Makefile to build libzpoline shared libraries from multiple source files

SRC_DIR := src
BUILD_DIR := output
EXAMPLE_DIR := example

SOURCES := $(wildcard $(SRC_DIR)/libzpoline*.c)
LIB_NAMES := $(foreach src,$(SOURCES),$(if $(filter $(SRC_DIR)/libzpoline.c,$(src)),libzpoline.so,$(patsubst $(SRC_DIR)/libzpoline%.c,libzpoline.so.%,$(src))))
TARGETS := $(patsubst %, $(BUILD_DIR)/%, $(LIB_NAMES))

CC := gcc
CFLAGS := -Wall -fPIC -O2 -shared
DEBUG_FLAGS := -Wall -fPIC -O0 -g -shared
LDFLAGS := -lcapstone -ldl

.PHONY: all debug clean

all: CFLAGS := $(CFLAGS)
all: $(BUILD_DIR) $(TARGETS) $(BUILD_DIR)/logger.so

debug: CFLAGS := $(DEBUG_FLAGS)
debug: $(BUILD_DIR) $(TARGETS)

$(BUILD_DIR):
	mkdir -p $@
# rule for libzpoline.so (no suffix)
$(BUILD_DIR)/libzpoline.so: $(SRC_DIR)/libzpoline.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# rule for libzpoline.so.N
$(BUILD_DIR)/libzpoline.so.%: $(SRC_DIR)/libzpoline%.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BUILD_DIR)/logger.so: $(SRC_DIR)/logger.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)
	rm -f main.c
	rm -f *.html *.html.*
	rm -f [vsyscall]

setup:
	sudo sh -c "echo 0 > /proc/sys/vm/mmap_min_addr"

run1:
	LD_PRELOAD=$(BUILD_DIR)/libzpoline.so.1 $(EXAMPLE_DIR)/ex1
run2:
	LD_PRELOAD=$(BUILD_DIR)/libzpoline.so.2 /usr/bin/echo '7h15 15 4 l337 73x7'
	LD_PRELOAD=$(BUILD_DIR)/libzpoline.so.2 /usr/bin/echo 'uphw{7h15_15_4_51mpl3_fl46_fr0m_200l4b}'
	LD_PRELOAD=$(BUILD_DIR)/libzpoline.so.2 cat $(EXAMPLE_DIR)/ex2-2.txt
run3:
	LD_PRELOAD=$(BUILD_DIR)/libzpoline.so LIBZPHOOK=$(EXAMPLE_DIR)/libex3hook.so $(EXAMPLE_DIR)/ex3
run4-1:
	LD_PRELOAD=$(BUILD_DIR)/libzpoline.so LIBZPHOOK=$(BUILD_DIR)/logger.so touch main.c
run4-2:
	LD_PRELOAD=$(BUILD_DIR)/libzpoline.so LIBZPHOOK=$(BUILD_DIR)/logger.so cat /etc/hosts
run5:
	LD_PRELOAD=$(BUILD_DIR)/libzpoline.so LIBZPHOOK=$(BUILD_DIR)/logger.so wget http://www.google.com -q -t 1
run6:
	LD_PRELOAD=$(BUILD_DIR)/libzpoline.so LIBZPHOOK=$(BUILD_DIR)/logger.so python3 -c 'import os; os.system("wget http://www.google.com -q -t 1")'
runh1-1:
	LD_PRELOAD=$(BUILD_DIR)/libzpoline.so LIBZPHOOK=$(BUILD_DIR)/logger.so cp $(EXAMPLE_DIR)/ex3 '[vsyscall]'
runh1-2:
	LD_PRELOAD=$(BUILD_DIR)/libzpoline.so LIBZPHOOK=$(BUILD_DIR)/logger.so ./'[vsyscall]'
runh2_s:
	LD_PRELOAD=$(BUILD_DIR)/libzpoline.so LIBZPHOOK=$(BUILD_DIR)/logger.so nc -lkU /tmp/hidden3.sock
runh2_c:
	LD_PRELOAD=$(BUILD_DIR)/libzpoline.so LIBZPHOOK=$(BUILD_DIR)/logger.so nc -U /tmp/hidden3.sock
runh3:
	LD_PRELOAD=$(BUILD_DIR)/libzpoline.so LIBZPHOOK=$(BUILD_DIR)/logger.so bash -c 'curl -s file:///etc/hosts'
runh4:
	LD_PRELOAD=$(BUILD_DIR)/libzpoline.so LIBZPHOOK=$(BUILD_DIR)/logger.so python3 -c 'import os; os.system("python3 -c '\''import os; os.system(\"id\")'\''")'