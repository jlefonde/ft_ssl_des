# ifndef DES_ECB_H
#  define DES_ECB_H

# include "ssl.h"

typedef struct s_command t_command;

void process_des_ecb(const t_command *cmd, int argc, char **argv);

# endif