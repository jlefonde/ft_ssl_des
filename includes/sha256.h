# ifndef SHA256_H
#  define SHA256_H

# include "ssl.h"

typedef struct s_input t_input;
typedef struct s_command t_command;

void *sha256(t_input *input);
void process_sha256(const t_command *cmd, int argc, char **argv);

# endif