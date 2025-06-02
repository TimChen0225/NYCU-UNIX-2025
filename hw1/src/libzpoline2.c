#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

extern void syscall_addr();
extern int64_t trigger_syscall(int64_t, int64_t, int64_t, int64_t, int64_t,
                               int64_t, int64_t);

void __raw_asm() {
  // trigger_syscall triggers a kernel-space system call
  asm volatile(".globl trigger_syscall\n\t"
               "trigger_syscall: \n\t"
               "movq %rdi, %rax \n\t"
               "movq %rsi, %rdi \n\t"
               "movq %rdx, %rsi \n\t"
               "movq %rcx, %rdx \n\t"
               "movq %r8, %r10 \n\t"
               "movq %r9, %r8 \n\t"
               "movq 8(%rsp),%r9 \n\t"
               ".globl syscall_addr \n\t"
               "syscall_addr: \n\t"
               "syscall \n\t"
               "ret \n\t");
}

int64_t handler(int64_t rdi, int64_t rsi, int64_t rdx, int64_t rcx, int64_t r8,
                int64_t r9, int64_t r10, int64_t rax) {

  if (rax == 1 && rdi == 1) { // write to stdout
    char *buf = (char *)rsi;
    size_t len = (size_t)rdx;

    char *newbuf = malloc(len);
    if (!newbuf)
      return -1;

    for (size_t i = 0; i < len; i++) {
      switch (buf[i]) {
      case '0':
        newbuf[i] = 'o';
        break;
      case '1':
        newbuf[i] = 'i';
        break;
      case '2':
        newbuf[i] = 'z';
        break;
      case '3':
        newbuf[i] = 'e';
        break;
      case '4':
        newbuf[i] = 'a';
        break;
      case '5':
        newbuf[i] = 's';
        break;
      case '6':
        newbuf[i] = 'g';
        break;
      case '7':
        newbuf[i] = 't';
        break;
      default:
        newbuf[i] = buf[i];
        break;
      }
    }

    long ret = trigger_syscall(rax, rdi, (int64_t)newbuf, rdx, r10, r8, r9);
    free(newbuf);
    return ret;
  }
  return trigger_syscall(rax, rdi, rsi, rdx, r10, r8, r9);
}

static void patch_syscalls() {
  FILE *fp = fopen("/proc/self/maps", "r");
  if (!fp) {
    fprintf(stderr, "Failed to open /proc/self/maps\n");
    return;
  }

  char line[512];
  while (fgets(line, sizeof(line), fp)) {
    if (strstr(line, "[stack]") || strstr(line, "[vsyscall]"))
      continue;

    uintptr_t from, to;
    char perms[5];
    if (sscanf(line, "%lx-%lx %4s", &from, &to, perms) != 3)
      continue;
    if (!strchr(perms, 'x'))
      continue;
    if (from == 0x0)
      continue;

    size_t len = to - from;
    uint8_t *region = (uint8_t *)from;
    mprotect((void *)from, len, PROT_READ | PROT_WRITE | PROT_EXEC);

    for (size_t i = 0; i + 1 < len; ++i) {
      if (region[i] == 0x0f && region[i + 1] == 0x05) {
        if ((uintptr_t)(region + i) == (uintptr_t)syscall_addr)
          continue;

        region[i] = 0xff; // call *%rax
        region[i + 1] = 0xd0;
        i++; // skip next byte
      }
    }
  }

  fclose(fp);
}

void trampoline() {
  asm volatile("pushq %rbp \n\t"
               "movq %rsp, %rbp \n\t"

               // stack is expected to be aligned to a 16 byte boundary.
               "andq $-16, %rsp \n\t" // 16 byte stack alignment

               /* assuming callee preserves r12-r15 and rbx  */
               "pushq %r11 \n\t"
               "pushq %r9 \n\t"
               "pushq %r8 \n\t"
               "pushq %rdi \n\t"
               "pushq %rsi \n\t"
               "pushq %rdx \n\t"
               "pushq %rcx \n\t"

               /* arguments for syscall_hook */
               "pushq %rax \n\t"
               "pushq %r10 \n\t"

               /* up to here, stack has to be 16 byte aligned */

               "callq handler \n\t"

               "popq %r10 \n\t"
               "addq $8, %rsp \n\t" // discard arg7

               "popq %rcx \n\t"
               "popq %rdx \n\t"
               "popq %rsi \n\t"
               "popq %rdi \n\t"
               "popq %r8 \n\t"
               "popq %r9 \n\t"
               "popq %r11 \n\t"

               "leaveq \n\t"

               "addq $128, %rsp \n\t"

               "retq \n\t");
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
  uint8_t patch[] = {
      0x48, 0x81, 0xec, 0x80, 0x00, 0x00, 0x00,          // sub $0x80, %rsp
      0x49, 0xbb, 0,    0,    0,    0,    0,    0, 0, 0, // movabs $addr, %r11
      0x41, 0xff, 0xe3                                   // jmp *%r11
  };
  uintptr_t hook_addr = (uintptr_t)trampoline;
  memcpy(patch + 9, &hook_addr, 8);

  uint8_t *p = (uint8_t *)mem;
  __builtin_memcpy(p + 512, patch, sizeof(patch));
}

__attribute__((constructor)) static void __trampoline_init(void) {
  setup_trampoline();
  patch_syscalls();
}