#include "ssl.h"

// #include <openssl/hmac.h>
#include <bsd/readpassphrase.h>

#define PASSWORD_MAX_LEN 128
#define SALT_LEN 8

// openssl enc -des-ecb -pbkdf2 -provider default -provider legacy -P
// openssl enc -des-ecb -pbkdf2 -provider default -provider legacy -pass pass:test -S "ABC" -P
void process_des_ecb(const t_command *cmd, int argc, char **argv)
{   
    t_context *ctx = parse_des(cmd, argc, argv);

    uint64_t input = 2;

    des(input);

    // int dk_len = 8;
    // int urandom_fd = open("/dev/urandom", O_RDONLY);
    // uint8_t salt[SALT_LEN]; 
    // ssize_t bytes_read = read(urandom_fd, salt, SALT_LEN);
    // close(urandom_fd);

    // char password[PASSWORD_MAX_LEN];
    // if (!readpassphrase("enter DES-ECB encryption password: ", password, PASSWORD_MAX_LEN, RPP_REQUIRE_TTY))
    //     return; // ERROR

    // char password_verify[PASSWORD_MAX_LEN];
    // if (!readpassphrase("Verifying - enter DES-ECB encryption password: ", password_verify, PASSWORD_MAX_LEN, RPP_REQUIRE_TTY))
    //     return; // ERROR

    // if (ft_strcmp(password, password_verify) != 0)
    // {
    //     print_error(cmd->name, "Password mismatch", NULL);
    //     return;
    // }

    // if (!ft_strlen(password))
    //     return; // NO PASSWORD GIVEN

    // uint8_t *dk = pbkdf2(hmac_sha256, 32, password, ft_strlen(password), salt, SALT_LEN, 1000, dk_len);

    // ft_printf("salt=");
    // for (int i = 0; i < SALT_LEN; i++)
    //     ft_printf("%02X", salt[i]);
    // ft_printf("\nkey=");
    // for (int i = 0; i < dk_len; i++)
    //     ft_printf("%02X", dk[i]);
    // ft_printf("\n");
    // free(dk);

    // unsigned char *out;
    // PKCS5_PBKDF2_HMAC(password, ft_strlen(password), salt, SALT_LEN, 1000, EVP_sha256(), dk_len, out);
    // printf("dk: ");
    // for (int i = 0; i < dk_len; i++)
    //     printf("%02X", out[i]);
    // printf("\n");
}
