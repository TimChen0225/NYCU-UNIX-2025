#pragma once
#include <string>

/* info 子指令的統一入口，目前只實作 info reg */
void cmd_info(const std::string &args);
