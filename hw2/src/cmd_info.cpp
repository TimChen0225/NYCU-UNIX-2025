#include "cmd_info.h"
#include "breakpoint.h" // 之後實作 info break 會用
#include "cmd_load.h"   // g_pid
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <vector>

namespace {

/* ------------------------------------------------------------------
 * 實作 info reg
 * ------------------------------------------------------------------ */
void info_registers() {
  user_regs_struct regs;
  if (ptrace(PTRACE_GETREGS, g_pid, nullptr, &regs) != 0) {
    perror("ptrace GETREGS");
    return;
  }

#define PRINT3(a, b, c)                                                        \
  std::printf("$%-3s 0x%016llx    $%-3s 0x%016llx    $%-3s 0x%016llx\n", #a,   \
              (unsigned long long)regs.a, #b, (unsigned long long)regs.b, #c,  \
              (unsigned long long)regs.c)

  PRINT3(rax, rbx, rcx);
  PRINT3(rdx, rsi, rdi);
  PRINT3(rbp, rsp, r8);
  PRINT3(r9, r10, r11);
  PRINT3(r12, r13, r14);
  PRINT3(r15, rip, eflags);

#undef PRINT3
}

/* 之後可在這裡加 info break / info XXX */
} // unnamed namespace

/* ------------------------------------------------------------------
 * public 入口：cmd_info()
 * ------------------------------------------------------------------ */
void cmd_info(const std::string &args) {
  if (g_pid == -1) {
    std::cerr << "** no program is loaded.\n";
    return;
  }

  std::istringstream iss(args);
  std::string sub;
  iss >> sub;

  if (sub == "reg") {
    info_registers();
  } else if (sub == "break") {
    if (g_bp_ids.empty()) {
      std::cout << "** no breakpoints.\n";
      return;
    }
    std::vector<std::pair<int, uint64_t>> list(g_bp_ids.begin(),
                                               g_bp_ids.end());
    std::sort(list.begin(), list.end(),
              [](auto &a, auto &b) { return a.first < b.first; });

    std::cout << "Num     Address\n";
    for (auto &[id, addr] : list)
      std::cout << id << "\t0x" << std::hex << addr << std::dec << '\n';
  } else {
    std::cerr << "** unknown command: info " << sub << '\n';
  }
}
