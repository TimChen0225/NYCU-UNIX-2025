#include "cmd_break.h"
#include "breakpoint.h"
#include "cmd_load.h" // g_pid, g_base
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/ptrace.h>
#include <sys/user.h>

/* ---------- 小工具：把字串轉 64-bit Hex ---------- */
static bool parse_hex(const std::string &s, uint64_t &out) {
  std::string t = s;
  if (t.rfind("0x", 0) == 0 || t.rfind("0X", 0) == 0)
    t.erase(0, 2);
  if (t.empty())
    return false;
  for (char c : t)
    if (!std::isxdigit(static_cast<unsigned char>(c)))
      return false;
  errno = 0;
  out = std::strtoull(t.c_str(), nullptr, 16);
  return errno == 0;
}

/* ---------- 實際安裝 INT3 斷點 & 記錄 ---------- */
static bool put_breakpoint(uint64_t addr) {
  if (g_breakpoints.count(addr)) {
    std::cout << "** breakpoint already exists.\n";
    return false;
  }

  /* -- 測試位址可否讀 -- */
  uint64_t aligned = addr & ~0x7ULL;
  errno = 0;
  ptrace(PTRACE_PEEKTEXT, g_pid, (void *)aligned, nullptr);
  if (errno) {
    std::cout << "** the target address is not valid.\n";
    return false;
  }

  /* -- 對齊並寫 INT3 (幾乎與 cmd_load 的 set_bp 相同) -- */
  Breakpoint bp;
  bp.addr = addr;
  aligned = addr & ~0x7ULL;
  unsigned shift = addr & 0x7ULL;

  uint64_t word = ptrace(PTRACE_PEEKTEXT, g_pid, (void *)aligned, nullptr);
  uint8_t *bytes = reinterpret_cast<uint8_t *>(&word);
  bp.saved_byte = bytes[shift];
  bytes[shift] = 0xCC;
  if (ptrace(PTRACE_POKEDATA, g_pid, (void *)aligned, (void *)word) != 0) {
    std::cout << "** failed to set breakpoint: " << std::strerror(errno)
              << "\n";
    return false;
  }
  bp.enabled = true;
  g_breakpoints[addr] = bp;

  /* -- 編號 & 回報 -- */
  g_bp_ids[g_next_id++] = addr;
  std::cout << "** set a breakpoint at 0x" << std::hex << addr << ".\n";
  return true;
}

/* ------------------------------------------------------------- */
/*                      public  handler                          */
/* ------------------------------------------------------------- */
void cmd_break(const std::string &args) {
  if (g_pid == -1) {
    std::cerr << "** no program is loaded.\n";
    return;
  }
  uint64_t addr;
  if (!parse_hex(args, addr)) {
    std::cerr << "** usage: break <hex address>\n";
    return;
  }
  put_breakpoint(addr);
}

void cmd_breakrva(const std::string &args) {
  if (g_pid == -1) {
    std::cerr << "** no program is loaded.\n";
    return;
  }
  uint64_t off;
  if (!parse_hex(args, off)) {
    std::cerr << "** usage: breakrva <hex offset>\n";
    return;
  }
  uint64_t addr = g_base + off;
  put_breakpoint(addr);
}
