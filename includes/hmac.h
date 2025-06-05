# ifndef HMAC_H
#  define HMAC_H

# include "ssl.h"

typedef struct s_hmac {
    size_t block_size;
    size_t out_len;
    void *(*digest_func)(t_input *input);
}   t_hmac;

void *hmac_sha256(uint8_t* key, size_t key_len, uint8_t* msg, size_t msg_len);

# endif