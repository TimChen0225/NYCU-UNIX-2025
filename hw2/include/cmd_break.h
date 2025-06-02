#pragma once
#include <string>

void cmd_break(const std::string &args);    // break <absolute addr>
void cmd_breakrva(const std::string &args); // breakrva <offset>
