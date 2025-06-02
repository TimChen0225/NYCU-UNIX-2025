#pragma once
#include <cstdint>
#include <sys/types.h>
#include <unordered_map>

/* 單一 breakpoint 需要記住「位置」與「原本的第一個 byte」 */
struct Breakpoint {
  uint64_t addr = 0;
  uint8_t saved_byte = 0;
  bool enabled = false;
};

/* 全域：addr → Breakpoint */
extern std::unordered_map<uint64_t, Breakpoint> g_breakpoints;

/* 新增： id → addr ；由 break / delete / info 共用 */
extern std::unordered_map<int, uint64_t> g_bp_ids;
extern int g_next_id;