#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

void my_handler() {
  const char *msg = "Hello from trampoline!\n";
  puts(msg);
}

static void setup_trampoline(void) {
  void *mem;

  /* allocate memory at virtual address 0 */
  mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
             MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);

  if (mem == MAP_FAILED) {
    fprintf(stderr, "map failed\n");
    fprintf(stderr, "NOTE: /proc/sys/vm/mmap_min_addr should be set 0\n");
    exit(1);
  }

  memset(mem, 0x90, 512);

  uint8_t *p = (uint8_t *)0x200;
  void *target = (void *)my_handler;
  int i = 0;

  // movabs r11, <addr>
  p[i++] = 0x49;
  p[i++] = 0xbb;
  memcpy(p + i, &target, sizeof(void *)); // 8 bytes
  i += 8;

  // jmp *r11
  p[i++] = 0x41;
  p[i++] = 0xff;
  p[i++] = 0xe3;

  assert(!mprotect(0, 0x1000, PROT_EXEC));
  puts("Trampoline setup complete.");
  fflush(stdout);
}

__attribute__((constructor(0xffff))) static void __zpoline_init(void) {
  setup_trampoline();
}