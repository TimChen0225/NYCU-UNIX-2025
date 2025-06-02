#pragma once
#include <string>

/* cmd_load.cpp 實作；其餘指令可照這個 prototype 新增 */
void cmd_load(const std::string &args);

/* === 全域狀態（給其他指令用）=== */
extern pid_t g_pid;      // 目前被除錯的子行程 (‒1 表示尚未 load)
extern uint64_t g_entry; // entry point (run-time 位址)
extern uint64_t g_base;  // main binary 的 base address (PIE 用)
