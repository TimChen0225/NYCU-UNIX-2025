#include "cmd_patch.h"
#include "breakpoint.h"
#include "cmd_load.h" // g_pid
#include <cerrno>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/ptrace.h>
#include <unistd.h>
#include <vector>

/* ------------- 工具：字串轉 hex bytes ---------------- */
static bool parse_hex_bytes(const std::string &hex, std::vector<uint8_t> &out) {
  if (hex.size() % 2 || hex.empty() || hex.size() > 2048)
    return false;
  out.clear();
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    char buf[3]{hex[i], hex[i + 1], 0};
    char *endp = nullptr;
    long val = strtol(buf, &endp, 16);
    if (*endp)
      return false;
    out.push_back(static_cast<uint8_t>(val));
  }
  return true;
}

/* ------------- 驗證位址可寫 ---------------- */
static bool address_valid(uint64_t addr, size_t len) {
  for (size_t off = 0; off < len; off += 8) {
    uint64_t aligned = (addr + off) & ~0x7ULL;
    errno = 0;
    ptrace(PTRACE_PEEKTEXT, g_pid, (void *)aligned, nullptr);
    if (errno)
      return false;
  }
  return true;
}

/* --------------------- public ------------------------ */
void cmd_patch(const std::string &args) {
  if (g_pid == -1) {
    std::cerr << "** no program is loaded.\n";
    return;
  }

  std::istringstream iss(args);
  std::string addr_str, hex_str;
  iss >> addr_str >> hex_str;

  if (addr_str.empty() || hex_str.empty()) {
    std::cerr << "** usage: patch <addr> <hex-bytes>\n";
    return;
  }

  /* 解析位址 */
  uint64_t addr = 0;
  try {
    addr = std::stoull(addr_str, nullptr, 16);
  } catch (...) {
    std::cerr << "** invalid address.\n";
    return;
  }

  /* 解析 hex 字串 */
  std::vector<uint8_t> bytes;
  if (!parse_hex_bytes(hex_str, bytes)) {
    std::cerr << "** invalid hex string.\n";
    return;
  }

  /* 位址合法性 */
  if (!address_valid(addr, bytes.size())) {
    std::cerr << "** the target address is not valid.\n";
    return;
  }

  /* 若覆蓋到斷點 → 更新 saved_byte，並保持 0xCC */
  for (size_t i = 0; i < bytes.size(); ++i) {
    uint64_t cur = addr + i;
    auto it = g_breakpoints.find(cur);
    if (it != g_breakpoints.end()) {
      it->second.saved_byte = bytes[i]; // 更新原 byte
      bytes[i] = 0xCC;                  // 記憶體仍放 int3
    }
  }

  /* 寫入 /proc/PID/mem */
  std::string mem_path = "/proc/" + std::to_string(g_pid) + "/mem";
  int fd = open(mem_path.c_str(), O_RDWR);
  if (fd < 0) {
    std::cerr << "** failed to open mem.\n";
    return;
  }
  if (pwrite(fd, bytes.data(), bytes.size(), addr) != (ssize_t)bytes.size()) {
    std::cerr << "** failed to write memory.\n";
    close(fd);
    return;
  }
  close(fd);

  std::cout << "** patch memory at 0x" << std::hex << addr << ".\n";
}
