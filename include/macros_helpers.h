#ifndef MACROS_HELPERS_H
#define MACROS_HELPERS_H

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "arts/skul.h"

#define CHECK_SYSCALL_OUT_IMPL_NO_RET(syscall, ...)                       \
  fprintf(stderr, SWORDSKUL);                                             \
  fprintf(stderr, "ERROR in %s:%d: %s failed - %s\n", __FILE__, __LINE__, \
          #syscall, strerror(errno));                                     \
  __VA_ARGS__;

#define CHECK_SYSCALL_OUT_IMPL(syscall, ...)          \
  CHECK_SYSCALL_OUT_IMPL_NO_RET(syscall, __VA_ARGS__) \
  return -1;

#define CHECK_SYSCALL_RES_IMPL(init, condition, value, syscall, ...) \
  do {                                                               \
    init = (syscall);                                                \
    if ((condition) == value) {                                      \
      CHECK_SYSCALL_OUT_IMPL(syscall, __VA_ARGS__);                  \
    }                                                                \
  } while (0)

#define CHECK_SYSCALL_RES_IMPL_NR(init, condition, value, syscall, ...) \
  do {                                                                  \
    init = (syscall);                                                   \
    if ((condition) == value) {                                         \
      CHECK_SYSCALL_OUT_IMPL_NO_RET(syscall, __VA_ARGS__);              \
    }                                                                   \
  } while (0)

#define CHECK_SYSCALL(syscall, ...) \
  CHECK_SYSCALL_RES_IMPL(int __result, __result, -1, syscall, __VA_ARGS__)

#define CHECK_SYSCALL_VAL(syscall, val, ...) \
  CHECK_SYSCALL_RES_IMPL(int __result, __result, val, syscall, __VA_ARGS__)

#define CHECK_SYSCALL_RES(result, syscall, ...) \
  CHECK_SYSCALL_RES_IMPL(result, result, -1, syscall, __VA_ARGS__)

#define CHECK_SYSCALL_RES_VAL(result, syscall, val, ...) \
  CHECK_SYSCALL_RES_IMPL(result, result, val, syscall, __VA_ARGS__)

#define CHECK_SYSCALL_NR(syscall, ...) \
  CHECK_SYSCALL_RES_IMPL_NR(int __result, __result, -1, syscall, __VA_ARGS__)

#define CHECK_SYSCALL_VAL_NR(syscall, val, ...) \
  CHECK_SYSCALL_RES_IMPL_NR(int __result, __result, val, syscall, __VA_ARGS__)

#define CHECK_SYSCALL_RES_NR(result, syscall, ...) \
  CHECK_SYSCALL_RES_IMPL_NR(result, result, -1, syscall, __VA_ARGS__)

#define CHECK_SYSCALL_RES_VAL_NR(result, syscall, val, ...) \
  CHECK_SYSCALL_RES_IMPL_NR(result, result, val, syscall, __VA_ARGS__)

#endif  // MACROS_HELPERS_H