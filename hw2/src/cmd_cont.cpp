#include "cmd_cont.h"
#include "breakpoint.h"
#include "cmd_load.h" // g_pid / g_entry
#include "disasm.h"

#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

namespace {

/* ---------------------------------------------------------
 *  工具：在 addr 設／拆 breakpoint，並更新 g_breakpoints
 * --------------------------------------------------------- */
bool enable_bp(pid_t pid, Breakpoint &bp) {
  if (bp.enabled)
    return true;

  uint64_t aligned = bp.addr & ~0x7ULL;
  unsigned shift = bp.addr & 0x7ULL;

  errno = 0;
  uint64_t data = ptrace(PTRACE_PEEKTEXT, pid, (void *)aligned, nullptr);
  if (errno)
    return false;

  uint8_t *bytes = reinterpret_cast<uint8_t *>(&data);
  bytes[shift] = 0xCC;

  if (ptrace(PTRACE_POKETEXT, pid, (void *)aligned, (void *)data) != 0)
    return false;

  bp.enabled = true;
  return true;
}

bool disable_bp(pid_t pid, Breakpoint &bp) {
  if (!bp.enabled)
    return true;

  uint64_t aligned = bp.addr & ~0x7ULL;
  unsigned shift = bp.addr & 0x7ULL;

  errno = 0;
  uint64_t data = ptrace(PTRACE_PEEKTEXT, pid, (void *)aligned, nullptr);
  if (errno)
    return false;

  uint8_t *bytes = reinterpret_cast<uint8_t *>(&data);
  bytes[shift] = bp.saved_byte;

  if (ptrace(PTRACE_POKETEXT, pid, (void *)aligned, (void *)data) != 0)
    return false;

  bp.enabled = false;
  return true;
}

/* ---------------------------------------------------------
 *  偵測子行程停止狀態，處理 EXIT / SIGNAL / BREAKPOINT
 * --------------------------------------------------------- */
bool handle_stop(pid_t pid, int status) {
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

  /* WIFSTOPPED */
  int sig = WSTOPSIG(status);
  if (sig != SIGTRAP) { // 其他 signal
    std::cout << "** stopped by signal " << sig << '\n';
    return false;
  }

  /* ---------------- 命中 breakpoint ---------------- */
  user_regs_struct regs;
  ptrace(PTRACE_GETREGS, pid, nullptr, &regs);

  uint64_t rip_hit = regs.rip - 1; // RIP 在 INT3 後面
  auto it = g_breakpoints.find(rip_hit);
  if (it == g_breakpoints.end()) {
    /* 應該不會發生：INT3 不是我們設的 */
    std::cout << "** hit unknown SIGTRAP at 0x" << std::hex << rip_hit
              << std::dec << '\n';
    return false;
  }

  Breakpoint &bp = it->second;
  /* 1. 拆 breakpoint，把原 byte 放回去 */
  disable_bp(pid, bp);

  /* 2. 把 RIP 調回原指令起點 */
  regs.rip = rip_hit;
  ptrace(PTRACE_SETREGS, pid, nullptr, &regs);

  std::cout << "** hit a breakpoint at 0x" << std::hex << rip_hit << std::dec
            << '\n';
  disasm_print(pid, rip_hit, 5);

  return true; // 已經停在下一條指令；回到主迴圈
}

} // unnamed namespace

/* ------------------------------------------------------------------ */
/*                          public  cmd_cont()                        */
/* ------------------------------------------------------------------ */
void cmd_cont(const std::string &args) {
  if (!args.empty()) {
    std::cerr << "** usage: cont   (no arguments)\n";
    return;
  }
  if (g_pid == -1) {
    std::cerr << "** no program is loaded.\n";
    return;
  }

  /* 將所有已啟用 breakpoint (過去可能因 single-step 關掉) 再確定打開 */
  for (auto &[addr, bp] : g_breakpoints) {
    enable_bp(g_pid, bp);
  }

  /* --- 若目前 RIP 正好在斷點，先滑過一次 --- */
  user_regs_struct regs0;
  ptrace(PTRACE_GETREGS, g_pid, nullptr, &regs0);
  auto it = g_breakpoints.find(regs0.rip);
  if (it != g_breakpoints.end()) {
    disable_bp(g_pid, it->second); // 拔 0xCC
    ptrace(PTRACE_SINGLESTEP, g_pid, nullptr, nullptr);
    int st;
    waitpid(g_pid, &st, 0);
    enable_bp(g_pid, it->second); // 補回 0xCC
  }
  /* --- 正式繼續執行直到下一事件 --- */
  if (ptrace(PTRACE_CONT, g_pid, nullptr, nullptr) != 0) {
    perror("ptrace CONT");
    return;
  }

  int status = 0;
  waitpid(g_pid, &status, 0);
  /* handle_stop 會印狀態 / 處理 breakpoint，並告訴我們是否還活著 */
  handle_stop(g_pid, status);
}
