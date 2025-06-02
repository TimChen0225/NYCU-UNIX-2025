#include "dispatch.h"
#include <iostream>
#include <sstream>
#include <string>

int main(int argc, char *argv[]) {
  /* sdb_cpp [program] ⇒ 自動做一次 load */
  if (argc == 2) {
    dispatch("load", argv[1]);
  }

  std::string line;
  while (true) {
    std::cout << "(sdb) " << std::flush;
    if (!std::getline(std::cin, line))
      break; // Ctrl-D → EOF
    if (line.empty())
      continue;

    std::istringstream iss(line);
    std::string cmd;
    iss >> cmd;
    std::string rest;
    std::getline(iss, rest); // 取得剩餘參數（含前導空白）

    if (cmd == "q" || cmd == "quit" || cmd == "exit")
      break;

    /* 去掉可能的領先空白 */
    if (!rest.empty() && rest.front() == ' ')
      rest.erase(0, 1);

    dispatch(cmd, rest);
  }
  return 0;
}
