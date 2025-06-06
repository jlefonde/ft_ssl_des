#include "ssl.h"

static uint8_t *F(void *(*prf)(uint8_t *key, size_t key_len, uint8_t *msg, size_t msg_len),
           size_t h_len,
           const char *password,
           size_t password_len,
           const uint8_t *salt,
           size_t salt_len,
           size_t c,
           uint32_t i)
{
    uint8_t *salt_i = malloc(salt_len + 4);
    if (!salt_i)
        return (NULL);

    ft_memcpy(salt_i, salt, salt_len);
    salt_i[salt_len] = (i >> 24) & 0xFF;
    salt_i[salt_len + 1] = (i >> 16) & 0xFF; 
    salt_i[salt_len + 2] = (i >> 8) & 0xFF; 
    salt_i[salt_len + 3] = i & 0xFF;

    uint8_t *u = prf(password, password_len, salt_i, salt_len + 4);
    free(salt_i);
    if (!u)
        return (NULL);

    uint8_t *res = malloc(h_len);
    if (!res)
    {
        free(u);
        return (NULL);
    }

    ft_memcpy(res, u, h_len);

    for (int j = 1; j < c; j++)
    {
        uint8_t *u_next = prf(password, password_len, u, h_len);
        if (!u_next)
        {
            free(u);
            free(res);
            return (NULL);
        }

        for (int k = 0; k < h_len; k++)
            res[k] ^= u_next[k];

        free(u);
        u = u_next;
    }

    free(u);
    return (res);
}

uint8_t *pbkdf2(
    void *(*prf)(uint8_t *key, size_t key_len, uint8_t *msg, size_t msg_len),
    size_t h_len,
    const char *password,
    size_t password_len, 
    const uint8_t *salt,
    size_t salt_len, 
    size_t c,
    int dk_len)
{
    size_t l = ceil((double)dk_len / (double)h_len);

    size_t r = dk_len - (l - 1) * h_len;

    uint8_t *dk = malloc(dk_len);
    if (!dk)
        return (NULL);
    for (int i = 0; i < l; i++)
    {
        uint8_t *t = F(prf, h_len, password, password_len, salt, salt_len, c, i + 1);

        ft_memcpy(dk + (h_len * i), t, ((i + 1) == l) ? r : h_len);
        free(t);
    }

    return (dk);
}
