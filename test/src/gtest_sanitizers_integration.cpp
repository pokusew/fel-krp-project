#include <gtest/gtest.h>

// GoogleTest Sanitizers Integration

// see https://google.github.io/googletest/advanced.html#sanitizer-integration
//     https://github.com/google/googletest/issues/3083

// see also https://github.com/google/sanitizers/issues/1191

// Sanitizers docs:
//   https://github.com/google/sanitizers


// https://lemire.me/blog/2022/08/20/catching-sanitizer-errors-programmatically/
// https://lemire.me/blog/2016/04/20/no-more-leaks-with-sanitize-flags-in-gcc-and-clang/
// https://lemire.me/blog/2019/05/16/building-better-software-with-better-tools-sanitizers-versus-valgrind/#comment-407539
// https://stackoverflow.com/questions/39686628/how-to-set-asan-ubsan-reporting-output

// TODO: Consider logging ASAN error to a separate log file (export ASAN_OPTIONS="log_path=asan.log")

// Note: How to find the following symbols in the LLVM source code:
//
//   1. git clone --depth=1 git@github.com:llvm/llvm-project.git
//   2. cd llvm-project
//   3. git grep -n __ubsan_on_report

extern "C" {

// https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/ubsan/ubsan_monitor.h#L35
// https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/ubsan/ubsan_monitor.cpp#L30
void __ubsan_on_report(void) {
	FAIL() << "Encountered an UndefinedBehaviorSanitizer error";
}

// https://github.com/llvm/llvm-project/blob/main/compiler-rt/include/sanitizer/asan_interface.h#L277
// https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/asan/asan_internal.h#L130
// https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/asan/asan_report.cpp#L143
void __asan_on_error(void) {
	FAIL() << "Encountered an AddressSanitizer error";
}

// https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/tsan/rtl/tsan_interface.h#L118
// https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/tsan/rtl/tsan_rtl_report.cpp#L663
void __tsan_on_report(void *report) {
	FAIL() << "Encountered a ThreadSanitizer error";
}

}  // extern "C"
