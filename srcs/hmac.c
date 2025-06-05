#include "ssl.h"

static uint8_t *pad_key(const t_hmac* hmac, uint8_t* key, size_t key_len)
{
    uint8_t *padded_key = malloc(hmac->block_size);
    if (!padded_key)
        return (NULL);

    if (key_len > hmac->block_size)
    {
        t_input input;
    
        input.type = INPUT_MEMORY;
        input.data = key;
        input.data_pos = 0;
        input.data_len = key_len;

        void *key_hash = hmac->digest_func(&input);
        ft_memcpy(padded_key, key_hash, hmac->out_len);
        key_len = hmac->out_len;

        free(key_hash);
    }
    else
        ft_memcpy(padded_key, key, key_len);

    ft_memset(padded_key + key_len, 0x00, hmac->block_size - key_len);
    return (padded_key);
}

static uint8_t *xor_key_with_pad(const t_hmac* hmac, uint8_t* key, uint8_t pad)
{
    uint8_t *res = malloc(hmac->block_size);
    if (!res)
        return (NULL);
    for (int i = 0; i < hmac->block_size; i++)
        res[i] = key[i] ^ pad;
    return (res);
}

static void *hmac(const t_hmac* hmac, uint8_t* key, size_t key_len, uint8_t* msg, size_t msg_len)
{
    uint8_t *padded_key = pad_key(hmac, key, key_len);

    uint8_t *key_opad = xor_key_with_pad(hmac, padded_key, 0x5C);
    uint8_t *key_ipad = xor_key_with_pad(hmac, padded_key, 0x36);
    free(padded_key);
    if (!key_opad || !key_ipad)
    {
        free(key_opad);
        free(key_ipad);
        return (NULL);
    }

    uint8_t *ipad_msg = ft_memjoin(key_ipad, hmac->block_size, msg, msg_len);
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
    in.data_len = hmac->block_size + msg_len;

    void *ihash = hmac->digest_func(&in);
    free(ipad_msg);

    uint8_t *opad_ihash = ft_memjoin(key_opad, hmac->block_size, ihash, hmac->out_len);
    free(key_opad);
    free(ihash);
    if (!opad_ihash)
        return (NULL);

    in.data = opad_ihash;
    in.data_pos = 0;
    in.data_len = hmac->block_size + hmac->out_len;

    void *res = hmac->digest_func(&in);
    free(opad_ihash);
    
    return (res);
}

void *hmac_sha256(uint8_t* key, size_t key_len, uint8_t* msg, size_t msg_len)
{
    t_hmac hm;

    hm.block_size = 64;
    hm.out_len = 32;
    hm.digest_func = sha256;

    return (hmac(&hm, key, key_len, msg, msg_len));
}
