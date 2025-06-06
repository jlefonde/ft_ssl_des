#include "ssl.h"

#include <openssl/hmac.h>

void process_des_ecb(const t_command *cmd, int argc, char **argv)
{    
    uint8_t password[] = "ABC123ABC123ABC123";
    uint8_t salt[] = "DEF456DEF456DEF456";
    uint8_t *dk = pbkdf2(hmac_sha256, 32, password, 18, salt, 18, 1000, 32);

    if (dk)
    {
        printf("KEY: ");
        for (int i = 0; i < 32; i++)
            printf("%02X", dk[i]);
        printf("\n");
    }
}
