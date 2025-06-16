# ifndef BASE64_H
#  define BASE64_H

# include "ssl.h"

# define BUFFER_SIZE 3072

typedef struct s_buffer
{
    uint8_t in[BUFFER_SIZE];
    char    out[BUFFER_SIZE];
    ssize_t bytes_read;
    size_t  total_bytes_written;
    size_t  out_pos;
}   t_buffer;

typedef struct s_command t_command;
typedef union u_context t_context;

void process_base64(const t_command *cmd, int argc, char **argv);
void clear_base64_ctx(t_context *ctx);

# endif
