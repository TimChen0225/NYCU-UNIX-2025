#include "cmd_load.h"
#include "disasm.h"

#include <elf.h>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits.h>
#include <sstream>
#include <string>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

/* ===== 全域狀態，供其餘指令使用 ===== */
pid_t g_pid = -1;
uint64_t g_entry = 0;
uint64_t g_base = 0;

/* ------------------------------------------------------------------ */
/*                          helper functions                           */
/* ------------------------------------------------------------------ */

/* 判斷執行檔是否為 ET_DYN (PIE / 動態連結) */
static bool is_dynamic_linked(const std::string &path) {
  std::ifstream elf(path, std::ios::binary);
  elf.seekg(0x10); // e_type 位置
  uint16_t e_type;
  elf.read(reinterpret_cast<char *>(&e_type), sizeof(e_type));
  return (e_type == ET_DYN);
}

/* 讀取 ELF header 的 e_entry（offset 形式） */
static uint64_t read_entry_offset(const std::string &path) {
  std::ifstream elf(path, std::ios::binary);
  elf.seekg(0x18); // e_entry 位置
  uint64_t off;
  elf.read(reinterpret_cast<char *>(&off), sizeof(off));
  return off;
}

/* 從 /proc/PID/maps 找 offset==0 的區段起始位址作為真正 base */
static uint64_t find_base(pid_t pid, const std::string &path) {
  char real_path[PATH_MAX];
  realpath(path.c_str(), real_path); // 取絕對路徑
  std::string abs = real_path;

  std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
  std::string line;
  while (std::getline(maps, line)) {
    if (line.find(abs) == std::string::npos)
      continue; // 非 main binary

    std::istringstream iss(line);
    std::string range, perms, offset_hex;
    iss >> range >> perms >> offset_hex;

    if (offset_hex != "00000000")
      continue; // 不是 offset 0

    size_t dash = range.find('-');
    uint64_t start = std::stoull(range.substr(0, dash), 0, 16);
    uint64_t off = std::stoull(offset_hex, 0, 16);
    return start - off; // 真正 base
  }
  return 0; // 不太可能發生
}

/* 以 /proc/PID/mem 暫設 int3，等待執行緒跑到指定 RIP */
static void wait_until_rip(pid_t pid, uint64_t target) {
  std::string mem = "/proc/" + std::to_string(pid) + "/mem";

  uint8_t orig;
  int fd = open(mem.c_str(), O_RDWR);
  pread(fd, &orig, 1, target);

  uint8_t int3 = 0xCC;
  pwrite(fd, &int3, 1, target);
  close(fd);

  ptrace(PTRACE_CONT, pid, nullptr, nullptr);
  int st;
  waitpid(pid, &st, 0);

  /* 修正 RIP 並還原原指令 */
  user_regs_struct regs;
  ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
  regs.rip = target;
  ptrace(PTRACE_SETREGS, pid, nullptr, &regs);

  fd = open(mem.c_str(), O_RDWR);
  pwrite(fd, &orig, 1, target);
  close(fd);
}

/* ------------------------------------------------------------------ */
/*                       public API:  cmd_load                         */
/* ------------------------------------------------------------------ */
void cmd_load(const std::string &path) {
  if (path.empty()) {
    std::cerr << "** usage: load <binary>\n";
    return;
  }
  if (g_pid != -1) {
    std::cerr << "** program already loaded.\n";
    return;
  }

  /* ---------- fork + exec ---------- */
  pid_t pid = fork();
  if (pid == 0) { // child
    ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
    execl(path.c_str(), path.c_str(), nullptr);
    perror("exec");
    _exit(1);
  }

  int status = 0;
  waitpid(pid, &status, 0); // 等 SIGSTOP
  ptrace(PTRACE_SETOPTIONS, pid, nullptr, PTRACE_O_TRACESYSGOOD);

  /* ---------- 判斷 PIE / 讀 entry offset ---------- */
  bool dynamic = is_dynamic_linked(path);
  uint64_t entry_off = read_entry_offset(path);

  /* ---------- 計算 g_base & g_entry ---------- */
  g_base = find_base(pid, path);
  if (g_base == 0)
    g_base = entry_off & ~0xfffULL;
  g_entry = dynamic ? (g_base + entry_off) : entry_off;

  /* ---------- 如果是 PIE，跑到真正 entry ---------- */
  // if (dynamic)
  wait_until_rip(pid, g_entry);

  /* ---------- 輸出 & disassemble ---------- */
  std::cout << "** program '" << path << "' loaded. entry point: 0x" << std::hex
            << g_entry << std::dec << ".\n";

  disasm_print(pid, g_entry, 5);

  g_pid = pid; // 留給其餘指令使用
}
