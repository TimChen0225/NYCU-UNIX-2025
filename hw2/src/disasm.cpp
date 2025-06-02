#include "disasm.h"
#include "breakpoint.h"
#include <capstone/capstone.h>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sys/ptrace.h>
#include <vector>

namespace {

static uint8_t safe_read_byte(pid_t pid, uint64_t a, bool &ok) {
  uint64_t aligned = a & ~0x7ULL;
  errno = 0;
  uint64_t word = ptrace(PTRACE_PEEKTEXT, pid, (void *)aligned, nullptr);
  if (errno) {
    ok = false;
    return 0;
  }
  ok = true;
  return reinterpret_cast<uint8_t *>(&word)[a & 0x7];
}

static std::vector<uint8_t> dump_mem(pid_t pid, uint64_t addr, size_t len) {
  std::vector<uint8_t> buf;
  buf.reserve(len);
  for (size_t i = 0; i < len; ++i) {
    bool ok;
    uint8_t b = safe_read_byte(pid, addr + i, ok);
    // std::cout << "try to get byte at 0x" << std::hex << (addr + i) << ": 0x"
    //           << std::setw(2) << std::setfill('0') << static_cast<int>(b)
    //           << std::dec << '\n';
    if (!ok)
      break; // 再往後不可讀就停
    buf.push_back(b);
  }
  return buf; // 可能 < len
}

} // unnamed namespace

/* ---------------- public API ---------------- */
void disasm_print(pid_t pid, uint64_t pc, unsigned count) {
  if (count == 0)
    return;

  constexpr size_t MAX_LEN_PER_INS = 15; // x86-64
  size_t raw_len = MAX_LEN_PER_INS * count;
  /* -------- 只抓得到「這一段可執行區域」內的 bytes -------- */
  /* 解析 /proc/PID/maps 找出包含 pc 的那一行，並取它的 end */
  uint64_t region_end = pc; // fallback: 只抓 1 byte
  {
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    std::string line;
    while (std::getline(maps, line)) {
      std::istringstream iss(line);
      std::string range, perms;
      iss >> range >> perms;

      if (perms.find("r-xp") == std::string::npos)
        continue;

      size_t dash = range.find('-');
      uint64_t start = std::stoull(range.substr(0, dash), 0, 16);
      uint64_t end = std::stoull(range.substr(dash + 1), 0, 16);
      if (pc >= start && pc < end) { // pc 落在此段
        region_end = end;
        break;
      }
    }
  }
  /* 不能跨出區段尾端 */
  // std::cout << "region_end: 0x" << std::hex << region_end << std::dec <<
  // '\n';
  uint64_t max_len_in_region = region_end - pc;
  if (raw_len > max_len_in_region)
    raw_len = max_len_in_region;

  /* 取 raw bytes */
  // std::cout << "pc: 0x" << std::hex << pc << ", raw_len: " << raw_len <<
  // '\n';
  auto raw = dump_mem(pid, pc, raw_len);

  /* ---- 把 0xCC 換回原 byte（避免出現在反組譯結果） ---- */
  extern std::unordered_map<uint64_t, Breakpoint> g_breakpoints;
  for (auto &[addr, bp] : g_breakpoints) {
    if (bp.enabled && addr >= pc && addr < pc + raw_len) {
      raw[addr - pc] = bp.saved_byte;
    }
  }

  /* capstone */
  csh handle;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
    std::cerr << "** capstone init fail\n";
    return;
  }
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);

  cs_insn *ins;
  size_t n = cs_disasm(handle, raw.data(), raw.size(), pc, count, &ins);

  for (size_t i = 0; i < n; ++i) {
    std::cout << "      0x" << std::hex << ins[i].address << ": ";

    /* raw bytes */
    for (size_t j = 0; j < ins[i].size; ++j)
      std::cout << std::setw(2) << std::setfill('0') << std::hex
                << static_cast<int>(ins[i].bytes[j]) << ' ';
    for (size_t p = ins[i].size; p < MAX_LEN_PER_INS; ++p)
      std::cout << "   ";

    std::cout << std::setw(8) << std::left << std::setfill(' ')
              << ins[i].mnemonic << ' ' << ins[i].op_str << std::dec << '\n';
  }
  // std::cout << "get disasm count: " << n << '\n';
  if (n < count)
    std::cout
        << "** the address is out of the range of the executable region.\n";

  cs_free(ins, n);
  cs_close(&handle);
}
