/* ------------------------------------------------------------------ */
/*                         src/cmd_syscall.cpp                        */
/* ------------------------------------------------------------------ */
#include "cmd_syscall.h"
#include "breakpoint.h" // g_breakpoints
#include "cmd_load.h"   // g_pid
#include "disasm.h"     // disasm_print

#include <cstring>
#include <iostream>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

long last_sc_nr = -1; // 用來記錄上一次進入 syscall 的系統呼叫號碼

/* ------------------------------------------------------------------ *
 * helper：啟用 / 停用單一 breakpoint （與 cmd_cont.cpp 中邏輯一致）
 * ------------------------------------------------------------------ */
static bool enable_bp(pid_t pid, Breakpoint &bp) {
  if (bp.enabled)
    return true;
  errno = 0;
  uint64_t data = ptrace(PTRACE_PEEKTEXT, pid, (void *)bp.addr, nullptr);
  if (errno)
    return false;
  bp.saved_byte = data & 0xFF;
  uint64_t patched = (data & ~0xFF) | 0xCC; // int3
  if (ptrace(PTRACE_POKEDATA, pid, (void *)bp.addr, (void *)patched) != 0)
    return false;
  bp.enabled = true;
  return true;
}

static bool disable_bp(pid_t pid, Breakpoint &bp) {
  if (!bp.enabled)
    return true;
  errno = 0;
  uint64_t data = ptrace(PTRACE_PEEKTEXT, pid, (void *)bp.addr, nullptr);
  if (errno)
    return false;
  uint64_t restored = (data & ~0xFF) | bp.saved_byte;
  if (ptrace(PTRACE_POKEDATA, pid, (void *)bp.addr, (void *)restored) != 0)
    return false;
  bp.enabled = false;
  return true;
}

/* ------------------------------------------------------------------ *
 * helper：如果當前 RIP 正踩在 breakpoint，先拆掉 0xCC、單步跳過，然後補回
 * （確保下一次 `syscall` 還能命中這個斷點）
 * ------------------------------------------------------------------ */
static void slide_over_current_bp() {
  user_regs_struct regs;
  ptrace(PTRACE_GETREGS, g_pid, nullptr, &regs);
  auto it = g_breakpoints.find(regs.rip);
  if (it == g_breakpoints.end())
    return;

  // 拆 int3
  disable_bp(g_pid, it->second);

  // 單步執行該位置原指令
  ptrace(PTRACE_SINGLESTEP, g_pid, nullptr, nullptr);
  int status;
  waitpid(g_pid, &status, 0);

  // 補回 int3
  enable_bp(g_pid, it->second);
}

/* ------------------------------------------------------------------ *
 * public: cmd_syscall
 *
 * 依 Spec 要求：在每次系統呼叫的「entry」與「exit」都停下，
 * 同時如果在此期間 hit 了 breakpoint，優先印出 breakpoint。
 * ------------------------------------------------------------------ */
void cmd_syscall(const std::string &args) {
  if (!args.empty()) {
    std::cerr << "** usage: syscall   (no arguments)\n";
    return;
  }
  if (g_pid == -1) {
    std::cerr << "** no program is loaded.\n";
    return;
  }

  // 1. 確保所有 breakpoint 都啟用
  for (auto &[_, bp] : g_breakpoints) {
    enable_bp(g_pid, bp);
  }
  // 2. 如果 RIP 正踩在某個 breakpoint，先跳過那條指令
  slide_over_current_bp();

  int status = 0;

  while (true) {
    // 3. 讓 tracee 進入下一個 syscall entry/exit
    if (ptrace(PTRACE_SYSCALL, g_pid, nullptr, nullptr) != 0) {
      perror("ptrace SYSCALL");
      return;
    }
    waitpid(g_pid, &status, 0);

    // 4. 如果程式已經結束 (exit 或 terminate)
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      std::cout << "** the target program terminated.\n";
      g_pid = -1;
      return;
    }

    // 5. 取得停下原因的 signal
    int sig = WSTOPSIG(status);

    // 6. 判斷是否因為 breakpoint 而停 （普通 SIGTRAP）
    if (sig == SIGTRAP) {
      user_regs_struct regs;
      ptrace(PTRACE_GETREGS, g_pid, nullptr, &regs);
      // 由於 PTRACE_SYSCALL 也會回 SIGTRAP，必須先檢查是否命中 breakpoint：
      // 如果 RIP-1 對應到某個 breakpoint，表示真的是斷點
      uint64_t rip_hit = regs.rip - 1;
      auto it = g_breakpoints.find(rip_hit);
      if (it != g_breakpoints.end()) {
        // 6a. 拆掉 breakpoint
        Breakpoint &bp = it->second;
        disable_bp(g_pid, bp);

        // 修正 RIP 回到原本 int3 的位址
        regs.rip = rip_hit;
        ptrace(PTRACE_SETREGS, g_pid, nullptr, &regs);

        // 印出訊息 & 反組譯 5 條
        std::cout << "** hit a breakpoint at 0x" << std::hex << rip_hit
                  << std::dec << ".\n";
        disasm_print(g_pid, rip_hit, 5);

        // 跳出 syscall loop，回到 prompt 等候使用者下一步指令
        return;
      }
    }

    // 7. 不是 breakpoint，而是 syscall 事件：SIGTRAP|0x80
    if (sig == (SIGTRAP | 0x80)) {
      // 7a. 取得 syscall 資訊 (號碼 & return value)
      struct __ptrace_syscall_info info;
      if (ptrace(PTRACE_GET_SYSCALL_INFO, g_pid, sizeof(info), &info) < 0) {
        perror("ptrace GET_SYSCALL_INFO");
        return;
      }

      // 7b. 讀目前 RIP
      user_regs_struct regs;
      ptrace(PTRACE_GETREGS, g_pid, nullptr, &regs);
      uint64_t sc_addr = regs.rip - 2; // syscall 指令位址

      // 7c. 如果是 entry，印出“enter a syscall”
      if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
        last_sc_nr = info.entry.nr;
        std::cout << "** enter a syscall(" << std::dec << last_sc_nr << std::hex
                  << ") at 0x" << sc_addr << ".\n";
        disasm_print(g_pid, sc_addr, 5);
        return;
      }
      // 7d. 如果是 exit，印出“leave a syscall”
      else if (info.op == PTRACE_SYSCALL_INFO_EXIT) {
        std::cout << "** leave a syscall(" << std::dec << last_sc_nr << std::hex
                  << ") = " << std::dec << info.exit.rval << std::hex
                  << " at 0x" << sc_addr << ".\n";
        disasm_print(g_pid, sc_addr, 5);
        return;
      }

      // 7e. 繼續下一個 PTRACE_SYSCALL 事件，不跳到 prompt
      continue;
    }

    // 8. 其他 signal，直接回 prompt
    std::cout << "** stopped by signal " << sig << ".\n";
    return;
  }
}
