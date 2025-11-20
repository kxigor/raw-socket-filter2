#ifndef MACROS_HELPERS_H
#define MACROS_HELPERS_H

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "arts/skul.h"

#define LOG(level, fmt, ...)                                                  \
  do {                                                                        \
    time_t now = time(NULL);                                                  \
    char timestamp[20];                                                       \
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S",               \
             localtime(&now));                                                \
    fprintf(stderr, "[%s] [%s] %s:%d: " fmt "\n", timestamp, level, __FILE__, \
            __LINE__, ##__VA_ARGS__);                                         \
  } while (0)

#define LOG_DEBUG(fmt, ...) LOG("DEBUG", fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) LOG("INFO", fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) LOG("WARN", fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) LOG("ERROR", fmt, ##__VA_ARGS__)

#define CHECK_SYSCALL_OUT_IMPL(init, result, syscall, expected, ret_call, ...) \
  do {                                                                         \
    init = syscall;                                                            \
    if (result == expected) {                                                  \
      fprintf(stderr, SWORDSKUL);                                              \
      LOG_ERROR("%s failed - %s\n", #syscall, strerror(errno))                 \
      __VA_ARGS__;                                                             \
      ret_call;                                                                \
    }                                                                          \
  } while (0)

#define CHECK_SYSCALL_NOE_OUT_IMPL(init, result, syscall, expected, ret_call, \
                                   ...)                                       \
  do {                                                                        \
    init = syscall;                                                           \
    if (result != expected) {                                                 \
      fprintf(stderr, SWORDSKUL);                                             \
      LOG_ERROR("%s failed - %s\n", #syscall, strerror(errno))                \
      __VA_ARGS__;                                                            \
      ret_call;                                                               \
    }                                                                         \
  } while (0)

#define WARN_SYSCALL_OUT_IMPL(init, result, syscall, expected, ret_call, ...) \
  do {                                                                        \
    init = syscall;                                                           \
    if (result == expected) {                                                 \
      fprintf(stderr, SWORDSKUL);                                             \
      LOG_WARN("%s failed - %s\n", #syscall, strerror(errno))                 \
      __VA_ARGS__;                                                            \
      ret_call;                                                               \
    }                                                                         \
  } while (0)

#define CHECK_SYSCALL(syscall, expected, ret_call, ...)                       \
  CHECK_SYSCALL_OUT_IMPL(int __result, __result, syscall, expected, ret_call, \
                         __VA_ARGS__)

#define CHECK_SYSCALL_RES(result, syscall, expected, ret_call, ...)   \
  CHECK_SYSCALL_OUT_IMPL(result, result, syscall, expected, ret_call, \
                         __VA_ARGS__)

#define CHECK_SYSCALL_NOE(syscall, expected, ret_call, ...)                   \
  CHECK_SYSCALL_OUT_IMPL(int __result, __result, syscall, expected, ret_call, \
                         __VA_ARGS__)

#define CHECK_SYSCALL_NOE_RES(result, syscall, expected, ret_call, ...) \
  CHECK_SYSCALL_OUT_IMPL(result, result, syscall, expected, ret_call,   \
                         __VA_ARGS__)

#define WARN_SYSCALL(syscall, expected, ...) \
  WARN_SYSCALL_OUT_IMPL(int __result, __result, syscall, expected, __VA_ARGS__)

#define WARN_SYSCALL_RES(result, syscall, expected, ...) \
  WARN_SYSCALL_OUT_IMPL(result, result, syscall, expected, __VA_ARGS__)

#endif  // MACROS_HELPERS_H