# ifndef BASE64_H
#  define BASE64_H

# include "ssl.h"

# define BASE64_BUFFER_SIZE 3072

typedef struct s_command t_command;
typedef union u_context t_context;

uint8_t *encode_base64_flag(const t_command *cmd, uint8_t *input, size_t n, size_t *encoded_size);
uint8_t *decode_base64_flag(const t_command *cmd, uint8_t *input, size_t n, size_t *decoded_size);
void process_base64(const t_command *cmd, int argc, char **argv);
void clear_base64_ctx(t_context *ctx);

# endif
