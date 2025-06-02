#include "dispatch.h"
#include "cmd_break.h"
#include "cmd_cont.h"
#include "cmd_delete.h"
#include "cmd_info.h"
#include "cmd_load.h"
#include "cmd_patch.h"
#include "cmd_si.h"
#include "cmd_syscall.h"
#include <fstream>
#include <functional>
#include <iostream>
#include <string>
#include <unordered_map>

/* === 指令對應的函式型別 === */
using CmdHandler = std::function<void(const std::string &)>;

/* === 全域指令表 === */
static const std::unordered_map<std::string, CmdHandler> table = {
    {"load", cmd_load},     {"si", cmd_si},       {"cont", cmd_cont},
    {"info", cmd_info},     {"break", cmd_break}, {"breakrva", cmd_breakrva},
    {"delete", cmd_delete}, {"patch", cmd_patch}, {"syscall", cmd_syscall},
};

/* === 分派 === */
void dispatch(const std::string &cmd, const std::string &args) {
  auto it = table.find(cmd);
  if (it == table.end()) {
    std::cerr << "** unknown command: " << cmd << '\n';
    return;
  }
  if (it->first != "load" && g_pid == -1) {
    std::cerr << "** please load a program first.\n";
    return;
  }
  it->second(args);
}
