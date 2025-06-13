# ifndef DES_H
#  define DES_H

# include "ssl.h"

#define PASSWORD_MAX_LEN 128
#define DES_SALT_LEN 8
#define DES_KEY_LEN 8
#define DES_IV_LEN 8
#define DES_PBKDF_ITR 1000

typedef struct s_command t_command;

void process_des_cbc(const t_command *cmd, int argc, char **argv);
void process_des_ecb(const t_command *cmd, int argc, char **argv);

# endif