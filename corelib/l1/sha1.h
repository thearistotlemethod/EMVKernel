#ifndef _SHA1_H_
#define _SHA1_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void compute_hash_str(uint8_t *buffer, int bufferlen, uint8_t digest[20]);

#ifdef __cplusplus
}
#endif
#endif // _SHA1_H_
