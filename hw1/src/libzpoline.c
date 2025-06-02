#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <dlfcn.h>
#include <errno.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>

extern int64_t trigger_syscall(int64_t, int64_t, int64_t, int64_t, int64_t,
                               int64_t, int64_t);
extern void syscall_addr();
extern void trampoline();

typedef int64_t (*syscall_hook_fn_t)(int64_t, int64_t, int64_t, int64_t,
                                     int64_t, int64_t, int64_t);

static syscall_hook_fn_t hook_fn = trigger_syscall;

void __raw_asm() {
  // trigger_syscall triggers a kernel-space system call
  asm volatile(".globl trigger_syscall\n\t"
               "trigger_syscall: \n\t"
               "movq 8(%rsp), %rax \n\t" // syscall number
               "movq %rcx, %r10 \n\t"    // arg4 → %r10
               ".globl syscall_addr \n\t"
               "syscall_addr: \n\t"
               "syscall \n\t"
               "ret \n\t");

  asm volatile(".globl trampoline \n\t"
               "trampoline: \n\t"

               "pushq %rbp \n\t"
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
               "pushq 136(%rbp) \n\t" // return address
               "pushq %rax \n\t"
               "pushq %r10 \n\t"

               /* up to here, stack has to be 16 byte aligned */

               "callq handler \n\t"

               "popq %r10 \n\t"
               "addq $16, %rsp \n\t" // discard arg7 and arg8

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

int64_t handler(int64_t rdi, int64_t rsi, int64_t rdx, int64_t rcx, int64_t r8,
                int64_t r9, int64_t r10, int64_t rax, int64_t retptr) {
  if (rax == 435 /* __NR_clone3 */) {
    uint64_t *ca = (uint64_t *)rdi; /* struct clone_args */
    if (ca[0] /* flags */ & CLONE_VM) {
      ca[6] /* stack_size */ -= sizeof(uint64_t);
      *((uint64_t *)(ca[5] /* stack */ + ca[6] /* stack_size */)) = retptr;
    }
  }

  if (rax == __NR_clone) {
    if (rdi & CLONE_VM) { // pthread creation
      /* push return address to the stack */
      rsi -= sizeof(uint64_t);
      *((uint64_t *)rsi) = retptr;
    }
  }
  return hook_fn(rdi, rsi, rdx, r10, r8, r9, rax);
}

static void patch_syscalls() {
  // open /proc/self/maps
  FILE *fp = fopen("/proc/self/maps", "r");
  if (!fp) {
    perror("fopen /proc/self/maps");
    exit(EXIT_FAILURE);
  }
  // initialize Capstone Disassembler
  csh handle;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
    fprintf(stderr, "[zpoline] cs_open failed\n");
    exit(EXIT_FAILURE);
  }
  cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

  char line[512];
  while (fgets(line, sizeof(line), fp)) {
    // ignore stack/vdso/vsyscall/self
    if (strstr(line, "[stack]") || strstr(line, "[vdso]") ||
        strstr(line, "libzpoline.so"))
      continue;

    char *last_slash = strrchr(line, '/');
    if (!last_slash && (strstr(line, "[vsyscall]"))) {
      continue;
    }

    uintptr_t start, end;
    char perm[5], path[512] = "";
    // get start and end addr, permission, and path
    if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %511[^\n]", &start, &end, perm,
               path) < 3)
      continue;
    if (!strchr(perm, 'x') || start == 0)
      continue;

    size_t size = end - start;
    uint8_t *code = (uint8_t *)start;
    if (mprotect(code, size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
      perror("[zpoline] mprotect");
      continue;
    }
    // use Capstone disasm whole section
    cs_insn *insn;
    size_t count = cs_disasm(handle, code, size, (uint64_t)start, 0, &insn);
    if (count == 0) {
      fprintf(stderr, "[zpoline] cs_disasm failed at %lx\n", start);
      continue;
    }

    for (size_t i = 0; i < count; i++) {
      // ignore rewrite trigger_syscall (my syscall)
      // syscall enum ID in Capstone is X86_INS_SYSCALL
      if (insn[i].id == X86_INS_SYSCALL &&
          (uintptr_t)insn[i].address != (uintptr_t)syscall_addr) {
        uint8_t *ptr = (uint8_t *)insn[i].address;
        // change syscall to call *%rax
        ptr[0] = 0xff; // call
        ptr[1] = 0xd0; // *%rax
      }
    }

    cs_free(insn, count);
    mprotect(code, size, PROT_READ | PROT_EXEC);
  }

  cs_close(&handle);
  fclose(fp);
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

static void load_hook_lib(void) {

  const char *filename = getenv("LIBZPHOOK");
  if (!filename) {
    fprintf(stderr, "env LIBZPHOOK is empty, so skip to load a hook library\n");
    return;
  }

  void *handle = dlmopen(LM_ID_NEWLM, filename, RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    fprintf(stderr, "dlmopen failed: %s\n\n", dlerror());
    fprintf(stderr,
            "NOTE: this may occur when the compilation of your hook function "
            "library misses some specifications in LDFLAGS. or if you are "
            "using a C++ compiler, dlmopen may fail to find a symbol, and "
            "adding 'extern \"C\"' to the definition may resolve the issue.\n");
    exit(1);
  }

  void (*hook_init)(syscall_hook_fn_t, syscall_hook_fn_t *) =
      dlsym(handle, "__hook_init");
  hook_init = dlsym(handle, "__hook_init");
  hook_init(trigger_syscall, &hook_fn);
}

__attribute__((constructor)) static void __trampoline_init(void) {
  setup_trampoline();
  patch_syscalls();
  load_hook_lib();
}