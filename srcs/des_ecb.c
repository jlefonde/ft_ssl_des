#include "ssl.h"

#include <openssl/hmac.h>

void process_des_ecb(const t_command *cmd, int argc, char **argv)
{
    uint8_t key[] = "ABC123";
    uint8_t msg[] = "test";

    uint8_t *digest = hmac_sha256(key, 6, msg, 4);
    if (!digest)
        exit(1);
    printf("HMAC: ");
    for (int i = 0; i < 32; ++i)
        printf("%02X", digest[i]);
    printf("\n");

    free(digest);

    unsigned int digest_len;
    unsigned char *digest2 = HMAC(EVP_sha256(), key, 6, msg, strlen((char *)msg), NULL, &digest_len);
    printf("HMAC: ");
    for (int i = 0; i < digest_len; ++i)
        printf("%02X", digest2[i]);
    printf("\n");
}
