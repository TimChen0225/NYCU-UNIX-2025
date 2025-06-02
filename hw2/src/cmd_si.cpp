#include "cmd_si.h"
#include "breakpoint.h"
#include "cmd_load.h" // 共用 g_pid / g_entry
#include "disasm.h"
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

namespace {

bool do_single_step(pid_t pid) {
  if (ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr) != 0) {
    perror("ptrace SINGLESTEP");
    return false;
  }

  int status = 0;
  waitpid(pid, &status, 0);

  if (WIFEXITED(status)) {
    // std::cout << "** the program finished with exit code "
    //           << WEXITSTATUS(status) << ".\n";
    std::cout << "** the target program terminated.\n";
    g_pid = -1;
    return false;
  }
  if (WIFSIGNALED(status)) {
    // std::cout << "** the program was terminated by signal " <<
    // WTERMSIG(status) << ".\n";
    std::cout << "** the target program terminated.\n";
    g_pid = -1;
    return false;
  }
  /* 期待 WIFSTOPPED(status) && WSTOPSIG(status)==SIGTRAP */
  return true;
}

} // unnamed namespace

/* ------------------------------------------------------------------ */
/*                        public  cmd_si()                             */
/* ------------------------------------------------------------------ */
void cmd_si(const std::string &args) {
  if (!args.empty()) {
    std::cerr << "** usage: si   (no arguments)\n";
    return;
  }
  if (g_pid == -1) {
    std::cerr << "** no program is loaded.\n";
    return;
  }

  /* ---- 如果 RIP 目前就在斷點上，先暫時恢復原 byte ---- */
  user_regs_struct cur;
  ptrace(PTRACE_GETREGS, g_pid, nullptr, &cur);
  auto it_bp = g_breakpoints.find(cur.rip);
  if (it_bp != g_breakpoints.end()) {
    Breakpoint &bp = it_bp->second;
    uint64_t aligned = bp.addr & ~0x7ULL;
    uint64_t word = ptrace(PTRACE_PEEKTEXT, g_pid, (void *)aligned, nullptr);
    uint8_t *bytes = reinterpret_cast<uint8_t *>(&word);
    bytes[bp.addr & 0x7] = bp.saved_byte; // 恢復原 byte
    ptrace(PTRACE_POKEDATA, g_pid, (void *)aligned, (void *)word);
  }

  do_single_step(g_pid);

  /* 取得最新 RIP，判斷是否命中 breakpoint ----------------------- */
  user_regs_struct regs;
  ptrace(PTRACE_GETREGS, g_pid, nullptr, &regs);

  bool hit = false;
  auto it2 = g_breakpoints.find(regs.rip);
  if (it2 != g_breakpoints.end()) {
    hit = true;
    std::cout << "** hit a breakpoint at 0x" << std::hex << regs.rip << std::dec
              << ".\n";
  }

  /* 若當初有暫時拆掉，現在補回 INT3 ----------------------------- */
  if (it_bp != g_breakpoints.end()) {
    Breakpoint &bp = it_bp->second;
    uint64_t aligned = bp.addr & ~0x7ULL;
    uint64_t word = ptrace(PTRACE_PEEKTEXT, g_pid, (void *)aligned, nullptr);
    uint8_t *bytes = reinterpret_cast<uint8_t *>(&word);
    bytes[bp.addr & 0x7] = 0xCC;
    ptrace(PTRACE_POKEDATA, g_pid, (void *)aligned, (void *)word);
  }

  /* disassemble 5 條（跟 spec 一致） ---------------------------- */
  disasm_print(g_pid, regs.rip, 5);
}
