#include "cmd_delete.h"
#include "breakpoint.h"
#include "cmd_load.h" // g_pid
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h> // open, O_RDWR
#include <iostream>
#include <sys/ptrace.h>
#include <unistd.h> // pwrite, close

/* 還原指定位址的原 byte（若目前仍啟用） */
/* ---- 利用 /proc/PID/mem 單 byte 寫回原值 ---- */
static bool restore_byte(uint64_t addr, const Breakpoint &bp) {
  // if (!bp.enabled)
  //   return true; // 已經還原

  std::string mem_path = "/proc/" + std::to_string(g_pid) + "/mem";
  int fd = open(mem_path.c_str(), O_RDWR);
  if (fd < 0)
    return false;

  ssize_t n = pwrite(fd, &bp.saved_byte, 1, addr);
  close(fd);
  return n == 1;
}

/* ---------------- public: cmd_delete ---------------- */
void cmd_delete(const std::string &args) {
  if (g_pid == -1) {
    std::cerr << "** no program is loaded.\n";
    return;
  }

  /* 1. 解析 id（十進位） */
  if (args.empty()) {
    std::cerr << "** usage: delete <id>\n";
    return;
  }
  char *endp = nullptr;
  long id = std::strtol(args.c_str(), &endp, 10);
  if (*endp != '\0' || id < 0) {
    std::cerr << "** usage: delete <id>\n";
    return;
  }

  /* 2. 檢查 breakpoint 是否存在 */
  auto it_id = g_bp_ids.find(static_cast<int>(id));
  if (it_id == g_bp_ids.end()) {
    std::cout << "** breakpoint " << id << " does not exist.\n";
    return;
  }
  uint64_t addr = it_id->second;

  auto it_bp = g_breakpoints.find(addr);
  if (it_bp == g_breakpoints.end()) {
    std::cout << "** breakpoint " << id << " does not exist.\n";
    return;
  }
  Breakpoint &bp = it_bp->second;

  /* 3. 若仍啟用，先把原 byte 補回去 */
  if (!restore_byte(addr, bp)) {
    std::cerr << "** failed to restore original byte: " << std::strerror(errno)
              << "\n";
    return;
  }

  /* 4. 從兩張表刪除 */
  g_breakpoints.erase(it_bp);
  g_bp_ids.erase(it_id);

  std::cout << "** delete breakpoint " << id << ".\n";
}
