#include "got_map.h"
#include "libgotoku.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

static gotoku_t *board = NULL;
static gotoku_t solved;
static int current_cmd = 0;
static int x = 0, y = 0;

static uintptr_t main_runtime_addr = 0;
static uintptr_t main_symbol_offset = 0x16c89;

void set_main_address(uintptr_t runtime_addr) {
  main_runtime_addr = runtime_addr;
}

uintptr_t get_got_entry_address(int cmd_index) {
  if (cmd_index < 0 || cmd_index >= sizeof(got_hooks) / sizeof(got_hooks[0])) {
    return 0;
  }

  uintptr_t base_addr = main_runtime_addr - main_symbol_offset;
  return base_addr + got_hooks[cmd_index].got_offset;
}

void make_writable(void *addr) {
  uintptr_t page_size = sysconf(_SC_PAGESIZE);
  uintptr_t page_start = (uintptr_t)addr & ~(page_size - 1);
  if (mprotect((void *)page_start, page_size,
               PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    perror("mprotect");
  }
}

void replace_gop_to_call(void *target_func_ptr) {
  if (!main_runtime_addr) {
    return;
  }
  // printf("SOLVER: replace_gop_to_call %d\n", current_cmd);

  uintptr_t target_got_addr = get_got_entry_address(current_cmd);
  if (target_got_addr == 0)
    return;

  make_writable((void *)target_got_addr);
  uintptr_t *entry = (uintptr_t *)target_got_addr;
  *entry = (uintptr_t)target_func_ptr;

  current_cmd += 1;
}

void move_to(int target_x, int target_y) {
  while (x < target_x) {
    replace_gop_to_call(&gop_right);
    ++x;
  }
  while (x > target_x) {
    replace_gop_to_call(&gop_left);
    --x;
  }
  while (y < target_y) {
    replace_gop_to_call(&gop_down);
    ++y;
  }
  while (y > target_y) {
    replace_gop_to_call(&gop_up);
    --y;
  }
}

void fill_number(int n) {
  switch (n) {
  case 1:
    replace_gop_to_call(&gop_fill_1);
    break;
  case 2:
    replace_gop_to_call(&gop_fill_2);
    break;
  case 3:
    replace_gop_to_call(&gop_fill_3);
    break;
  case 4:
    replace_gop_to_call(&gop_fill_4);
    break;
  case 5:
    replace_gop_to_call(&gop_fill_5);
    break;
  case 6:
    replace_gop_to_call(&gop_fill_6);
    break;
  case 7:
    replace_gop_to_call(&gop_fill_7);
    break;
  case 8:
    replace_gop_to_call(&gop_fill_8);
    break;
  case 9:
    replace_gop_to_call(&gop_fill_9);
    break;
  }
}

int solve_sudoku(int y, int x) {
  if (y == 9)
    return 1;
  if (solved.board[y][x] != 0) {
    return solve_sudoku(x == 8 ? y + 1 : y, (x + 1) % 9);
  }

  for (int n = 1; n <= 9; ++n) {
    int ok = 1;
    for (int i = 0; i < 9; ++i) {
      if (solved.board[y][i] == n || solved.board[i][x] == n ||
          solved.board[(y / 3) * 3 + i / 3][(x / 3) * 3 + i % 3] == n) {
        ok = 0;
        break;
      }
    }
    if (!ok)
      continue;

    solved.board[y][x] = n;
    if (solve_sudoku(x == 8 ? y + 1 : y, (x + 1) % 9))
      return 1;
    solved.board[y][x] = 0;
  }
  return 0;
}

void replay_solution() {
  for (int y = 0; y < 9; ++y) {
    for (int x = 0; x < 9; ++x) {
      // printf("SOLVER: %d %d %d\n", y, x, solved.board[y][x]);
      if (board->board[y][x] != 0)
        continue;
      move_to(x, y);
      fill_number(solved.board[y][x]);
    }
  }
}

int game_init() {
  printf("UP113_GOT_PUZZLE_CHALLENGE\n");
  void *main_ptr = game_get_ptr();
  printf("SOLVER: _main =  %p\n", main_ptr);

  board = game_load("/gotoku.txt");
  if (!board)
    return -1;

  set_main_address((uintptr_t)main_ptr);

  for (int y = 0; y < 9; ++y) {
    for (int x = 0; x < 9; ++x) {
      solved.board[y][x] = board->board[y][x];
    }
  }

  if (!solve_sudoku(0, 0)) {
    fprintf(stderr, "Failed to solve sudoku!\n");
    return -1;
  }
  printf("SOLVER: Solved Sudoku\n");

  replay_solution();
  printf("SOLVER: Replay solution finish\n");
  return 0;
}
