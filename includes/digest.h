# ifndef DIGEST_H
#  define DIGEST_H

# include "ssl.h"

typedef struct s_command t_command;
typedef union u_context t_context;

t_context *parse_digest(const t_command *cmd, int argc, char **argv);
void process_digest(const t_command *cmd, t_context *ctx);
void clear_digest_ctx(t_context *ctx);

# endif