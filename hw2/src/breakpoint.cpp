#include "breakpoint.h"
std::unordered_map<uint64_t, Breakpoint> g_breakpoints; // 全域定義

std::unordered_map<int, uint64_t> g_bp_ids;
int g_next_id = 0;