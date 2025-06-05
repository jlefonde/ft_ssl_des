#include "ssl.h"

#define SHA256_BLOCK_SIZE 64
#define SHA256_OUT_LEN 32

static uint8_t *pad_key(uint8_t* key, size_t key_len)
{
    uint8_t *padded_key = malloc(SHA256_BLOCK_SIZE);
    if (!padded_key)
        return (NULL);

    if (key_len > SHA256_BLOCK_SIZE)
    {
        t_input input;
    
        input.type = INPUT_MEMORY;
        input.data = key;
        input.data_pos = 0;
        input.data_len = key_len;

        void *key_hash = sha256(&input);
        ft_memcpy(padded_key, key_hash, SHA256_OUT_LEN);
        key_len = SHA256_OUT_LEN;

        free(key_hash);
    }
    else
        ft_memcpy(padded_key, key, key_len);

    ft_memset(padded_key + key_len, 0x00, SHA256_BLOCK_SIZE - key_len);
    return (padded_key);
}

static uint8_t *xor_key_with_pad(uint8_t* key, uint8_t pad)
{
    uint8_t *res = malloc(SHA256_BLOCK_SIZE);
    if (!res)
        return (NULL);
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++)
        res[i] = key[i] ^ pad;
    return (res);
}

uint8_t *hmac_sha256(uint8_t* key, size_t key_len, uint8_t* msg, size_t msg_len)
{
    uint8_t *padded_key = pad_key(key, key_len);

    uint8_t *key_opad = xor_key_with_pad(padded_key, 0x5C);
    uint8_t *key_ipad = xor_key_with_pad(padded_key, 0x36);
    free(padded_key);
    if (!key_opad || !key_ipad)
    {
        free(key_opad);
        free(key_ipad);
        return (NULL);
    }

    uint8_t *ipad_msg = ft_memjoin(key_ipad, SHA256_BLOCK_SIZE, msg, msg_len);
    free(key_ipad);
    if (!ipad_msg)
    {
        free(key_opad);
        return (NULL);
    }

    t_input in;
    in.type = INPUT_MEMORY;
    in.data = ipad_msg;
    in.data_pos = 0;
    in.data_len = SHA256_BLOCK_SIZE + msg_len;

    void *ihash = sha256(&in);
    free(ipad_msg);

    uint8_t *opad_ihash = ft_memjoin(key_opad, SHA256_BLOCK_SIZE, ihash, SHA256_OUT_LEN);
    free(key_opad);
    free(ihash);
    if (!opad_ihash)
        return (NULL);

    in.data = opad_ihash;
    in.data_pos = 0;
    in.data_len = SHA256_BLOCK_SIZE + SHA256_OUT_LEN;

    void *res = sha256(&in);
    free(opad_ihash);
    
    return (res);
}
