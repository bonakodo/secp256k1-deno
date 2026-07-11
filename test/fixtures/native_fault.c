#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>

extern void secp256k1_selftest(void);

void secp256k1_fault_link_anchor(void) {
  secp256k1_selftest();
}

#if defined(FAULT_SYMBOL)
typedef int (*fault_function)(
    uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t,
    uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);

#define STRINGIFY_INNER(value) #value
#define STRINGIFY(value) STRINGIFY_INNER(value)

int FAULT_SYMBOL(
    uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5,
    uintptr_t a6, uintptr_t a7, uintptr_t a8, uintptr_t a9, uintptr_t a10) {
  static unsigned int calls = 0;
  calls++;
#if !defined(FAIL_CALL)
#define FAIL_CALL 1
#endif
  if (calls == FAIL_CALL) {
#if defined(ZERO_SECOND_OUTPUT)
    memset((void *)a2, 0, 64);
    return 1;
#else
    return 0;
#endif
  }
  fault_function function =
      (fault_function)dlsym(RTLD_NEXT, STRINGIFY(FAULT_SYMBOL));
  return function(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
}
#elif defined(NULL_POINTER_SYMBOL)
const void *NULL_POINTER_SYMBOL = NULL;
#elif defined(TAGGED_HASH_ORDER) || defined(TAGGED_HASH_OVER_ORDER)
int secp256k1_tagged_sha256(
    const void *context,
    unsigned char *output,
    const unsigned char *tag,
    size_t tag_length,
    const unsigned char *message,
    size_t message_length) {
  static const unsigned char order[32] = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
      0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
      0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
  };
  (void)context;
  (void)tag;
  (void)tag_length;
  (void)message;
  (void)message_length;
  memcpy(output, order, sizeof(order));
#if defined(TAGGED_HASH_OVER_ORDER)
  output[31]++;
#endif
  return 1;
}
#else
#error "A native fault must be selected"
#endif
