# ifndef BASE64_H
#  define BASE64_H

# include "ssl.h"

# define BUFFER_SIZE 64

typedef struct s_command t_command;

void process_base64(const t_command *cmd, int argc, char **argv);

# endif