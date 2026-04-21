#include <sodium.h>
#include <stddef.h>
#include <stdint.h>

void randombytes(uint8_t *out, size_t outlen)
{
    randombytes_buf(out, outlen);
}
