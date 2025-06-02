#pragma once
#include <string>

/**
 * single-step：預設執行 1 個指令。
 * 若子行程已結束或尚未 load，會輸出錯誤訊息。
 */
void cmd_si(const std::string &args);
