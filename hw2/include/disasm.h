#pragma once
#include <cstdint>
#include <sys/types.h> // pid_t

/**
 * 反組譯並印出 count 條指令（預設 5 條）。
 * @param pid    子行程 pid（必須已經被 ptrace 附著、且處於 STOP）
 * @param pc     起始位址 (runtime address)
 * @param count  要顯示幾條指令；預設 5
 *
 * 若位址超出可執行區域，會自動偵測並輸出警告訊息。
 */
void disasm_print(pid_t pid, uint64_t pc, unsigned count = 5);
