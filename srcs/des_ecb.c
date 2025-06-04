#include "ssl.h"

#define SHA256_BLOCK_SIZE 64
#define SHA256_OUT_LEN 32

uint32_t *hmac_sha256(uint8_t* key, size_t key_len, uint8_t* msg, size_t msg_len)
{
    t_input input;
    
    input.type = INPUT_RAW;
    
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

    ft_printf("Padded key: ");
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++)
        ft_printf("%02x", padded_key[i]);
    ft_printf("\n");

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

    printf("Inner hash input: ");
    for (int i = 0; i < SHA256_BLOCK_SIZE + msg_len; i++)
        printf("%02x", ((uint8_t*)key_xor_ipad_with_msg)[i]);
    printf("\n");
    void *hash_key_xor_ipad_with_msg = sha256(&input);
    printf("Inner hash: ");
    for (int i = 0; i < SHA256_OUT_LEN; i++)
        printf("%02x", ((uint8_t*)hash_key_xor_ipad_with_msg)[i]);
    printf("\n");

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
    printf("Outer hash input: ");
    for (int i = 0; i < SHA256_BLOCK_SIZE + SHA256_OUT_LEN; i++)
        printf("%02x", key_xor_opad_with_hash_key_xor_ipad_with_msg[i]);
    printf("\n");
    uint32_t *result = (uint32_t *)sha256(&input);

    free(padded_key);
    free(key_xor_opad);
    free(key_xor_ipad);
    free(key_xor_ipad_with_msg);
    free(hash_key_xor_ipad_with_msg);
    free(key_xor_opad_with_hash_key_xor_ipad_with_msg);
    
    return result;
}

void process_des_ecb(const t_command *cmd, int argc, char **argv)
{
    uint8_t key[3] = { 0xAB, 0xC1, 0x23 };
    uint8_t msg[4] = { 't', 'e', 's', 't' };
    
    // Debug: print key and message
    printf("Key: ");
    for (int i = 0; i < 3; i++)
        printf("%02x", key[i]);
    printf("\nMsg: ");
    for (int i = 0; i < 4; i++)
        printf("%02x", msg[i]);
    printf("\n");
    
    uint32_t *digest = hmac_sha256(key, 3, msg, 4);
    printf("HMAC: ");
    for (int i = 0; i < 8; ++i)
        printf("%08x", digest[i]);
    printf("\n");
    
    free(digest);
}