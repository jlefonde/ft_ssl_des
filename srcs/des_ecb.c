#include "ssl.h"

#define SHA256_BLOCK_SIZE 64
#define SHA256_OUT_LEN 32

uint32_t *hmac_sha256(uint8_t* key, size_t key_len, uint8_t* msg, size_t msg_len)
{
    t_input input;
    
    input.type = INPUT_MEMORY;
    
    uint8_t *padded_key = malloc(SHA256_BLOCK_SIZE);
    if (!padded_key)
        return (NULL);
    if (key_len > SHA256_BLOCK_SIZE)
    {
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

    uint8_t *key_xor_opad = malloc(SHA256_BLOCK_SIZE);
    if (!key_xor_opad)
    {
        free(padded_key);
        return (NULL);
    }
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++)
        key_xor_opad[i] = padded_key[i] ^ 0x5C;

    uint8_t *key_xor_ipad = malloc(SHA256_BLOCK_SIZE);
    if (!key_xor_ipad)
    {
        free(padded_key);
        free(key_xor_opad);
        return (NULL);
    }

    for (int i = 0; i < SHA256_BLOCK_SIZE; i++)
        key_xor_ipad[i] = padded_key[i] ^ 0x36;

    uint8_t *key_xor_ipad_with_msg = malloc(SHA256_BLOCK_SIZE + msg_len);
    if (!key_xor_ipad_with_msg)
    {
        free(padded_key);
        free(key_xor_opad);
        free(key_xor_ipad);
        return (NULL);
    }
    ft_memcpy(key_xor_ipad_with_msg, key_xor_ipad, SHA256_BLOCK_SIZE);
    ft_memcpy(key_xor_ipad_with_msg + SHA256_BLOCK_SIZE, msg, msg_len);

    input.data = key_xor_ipad_with_msg;
    input.data_pos = 0;
    input.data_len = SHA256_BLOCK_SIZE + msg_len;

    void *hash_key_xor_ipad_with_msg = sha256(&input);

    uint8_t *key_xor_opad_with_hash_key_xor_ipad_with_msg = malloc(SHA256_BLOCK_SIZE + SHA256_OUT_LEN);
    if (!key_xor_opad_with_hash_key_xor_ipad_with_msg)
    {
        free(padded_key);
        free(key_xor_opad);
        free(key_xor_ipad);
        free(key_xor_ipad_with_msg);
        return (NULL);
    }
    ft_memcpy(key_xor_opad_with_hash_key_xor_ipad_with_msg, key_xor_opad, SHA256_BLOCK_SIZE);
    ft_memcpy(key_xor_opad_with_hash_key_xor_ipad_with_msg + SHA256_BLOCK_SIZE, hash_key_xor_ipad_with_msg, SHA256_OUT_LEN);

    input.data = key_xor_opad_with_hash_key_xor_ipad_with_msg;
    input.data_pos = 0;
    input.data_len = SHA256_BLOCK_SIZE + SHA256_OUT_LEN;

    uint32_t *result = (uint32_t *)sha256(&input);

    free(padded_key);
    free(key_xor_opad);
    free(key_xor_ipad);
    free(key_xor_ipad_with_msg);
    free(hash_key_xor_ipad_with_msg);
    free(key_xor_opad_with_hash_key_xor_ipad_with_msg);
    
    return result;
}

#include <openssl/hmac.h>

void process_des_ecb(const t_command *cmd, int argc, char **argv)
{
    uint8_t key[] = "ABC123";
    uint8_t msg[] = "testqdsdsqqsd";

    uint32_t *digest = hmac_sha256(key, 6, msg, 13);
    printf("HMAC: ");
    for (int i = 0; i < 32; ++i)
        printf("%02x", ((uint8_t*)digest)[i]);
    printf("\n");

    free(digest);

    unsigned int digest_len;
    unsigned char *digest2 = HMAC(EVP_sha256(), key, 6, msg, strlen((char *)msg), NULL, &digest_len);
    printf("HMAC: ");
    for (int i = 0; i < digest_len; ++i)
        printf("%02x", digest2[i]);
    printf("\n");
    
}