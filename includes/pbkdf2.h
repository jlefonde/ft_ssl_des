# ifndef PBKDF2_H
#  define PBKDF2_H

# include <math.h>

# include "ssl.h"

uint8_t *pbkdf2(
    void *(*prf)(uint8_t *key, size_t key_len, uint8_t *msg, size_t msg_len),
    size_t hLen,
    const char *password,
    size_t password_len, 
    const uint8_t *salt,
    size_t salt_len, 
    size_t c,
    int dkLen);

# endif