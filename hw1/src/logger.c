#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/un.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

typedef int64_t (*syscall_hook_fn_t)(int64_t, int64_t, int64_t, int64_t,
                                     int64_t, int64_t, int64_t);

static syscall_hook_fn_t original_syscall = NULL;

static void escape_and_print(const char *buf, size_t len, FILE *out) {
  fputc('"', out);
  for (size_t i = 0; i < len && i < 32; ++i) {
    unsigned char c = buf[i];
    if (c == '\\')
      fputs("\\\\", out);
    else if (c == '\"')
      fputs("\\\"", out);
    else if (c == '\n')
      fputs("\\n", out);
    else if (c == '\r')
      fputs("\\r", out);
    else if (c == '\t')
      fputs("\\t", out);
    else if (c >= 32 && c < 127)
      fputc(c, out);
    else
      fprintf(out, "\\x%02x", c);
  }
  if (len > 32)
    fputs("...", out);
  fputc('"', out);
}

static int64_t syscall_hook_fn(int64_t rdi, int64_t rsi, int64_t rdx,
                               int64_t r10, int64_t r8, int64_t r9,
                               int64_t rax) {
  int64_t result;

  if (rax == SYS_execve) {
    fprintf(stderr, "[logger] execve(\"%s\", %p, %p)\n", (char *)rdi,
            (void *)rsi, (void *)r10);
  }

  result = original_syscall(rdi, rsi, rdx, r10, r8, r9, rax);

  switch (rax) {
  case SYS_openat:
    fprintf(stderr, "[logger] openat(%s, \"%s\", %#lx, %#o) = %ld\n",
            ((int)rdi == AT_FDCWD) ? "AT_FDCWD" : ({
              static char buf[32];
              snprintf(buf, sizeof(buf), "%ld", rdi);
              buf;
            }),
            (char *)rsi, rdx, (unsigned)r10, result);
    break;

  case SYS_read:
    fprintf(stderr, "[logger] read(%ld, ", rdi);
    escape_and_print((const char *)rsi, result, stderr);
    fprintf(stderr, ", %ld) = %ld\n", rdx, result);
    break;

  case SYS_write:
    fprintf(stderr, "[logger] write(%ld, ", rdi);
    escape_and_print((const char *)rsi, result, stderr);
    fprintf(stderr, ", %ld) = %ld\n", rdx, result);
    break;

  case SYS_connect: {
    char addrstr[256] = "-";
    if (rsi && rdx > 0) {
      struct sockaddr *sa = (struct sockaddr *)rsi;
      if (sa->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)sa;
        snprintf(addrstr, sizeof(addrstr), "%s:%d", inet_ntoa(in->sin_addr),
                 ntohs(in->sin_port));
      } else if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)sa;
        inet_ntop(AF_INET6, &in6->sin6_addr, addrstr, sizeof(addrstr));
        size_t len = strlen(addrstr);
        snprintf(addrstr + len, sizeof(addrstr) - len, ":%d",
                 ntohs(in6->sin6_port));
      } else if (sa->sa_family == AF_UNIX) {
        struct sockaddr_un *un = (struct sockaddr_un *)sa;
        snprintf(addrstr, sizeof(addrstr), "UNIX:%s", un->sun_path);
      }
    }
    fprintf(stderr, "[logger] connect(%ld, \"%s\", %ld) = %ld\n", rdi, addrstr,
            rdx, result);
    break;
  }

  default:
    break;
  }
  return result;
}

void __hook_init(const syscall_hook_fn_t trigger_syscall,
                 syscall_hook_fn_t *hooked_syscall) {
  // fprintf(stderr, "[logger] __hook_init called!\n");
  original_syscall = trigger_syscall;
  *hooked_syscall = syscall_hook_fn;
}
