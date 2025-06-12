#ifndef FT_SSL_H
# define FT_SSL_H

# include <stdbool.h>
# include <stdio.h>
# include <stdint.h>
# include <string.h>
# include <fcntl.h>
# include <unistd.h>
# include <stdlib.h>
# include <errno.h>
#include <bsd/readpassphrase.h>

# include "../libft/includes/libft.h"
# include "md5.h"
# include "sha256.h"
# include "blake2s.h"
# include "blake2b.h"
# include "base64.h"
# include "hmac.h"
# include "pbkdf2.h"
# include "des.h"

typedef enum e_category_type
{
    CATEGORY_DIGEST,
    CATEGORY_CIPHER
}	t_category_type;

typedef enum e_input_type
{
    INPUT_STDIN,
    INPUT_FILE,
    INPUT_MEMORY
}	t_input_type;

typedef struct s_input
{
    t_input_type    type;
    uint8_t         *data;
    size_t          data_len;
    size_t          data_pos;
    int             fd;
}	t_input;

typedef union u_context
{
    struct
    {
        bool    reverse_mode;
        bool    quiet_mode;
        bool    stdin_mode;
        bool    sum_mode;
        t_list  *inputs;
        void *(*cmd_func)(t_input *input);
        void (*print_func)(void *output);
    }	digest;

    struct
    {
        int     in;
        int     out;
        bool    decode_mode;
    }   base64;

    struct
    {
        int     in;
        int     out;
        char    *password;
        uint8_t *key;
        uint8_t *salt;
        uint8_t *iv;
        bool    base64_mode;
        bool    decrypt_mode;
        bool    print_mode;
    }   des;
}	t_context;

typedef struct s_category
{
    const char *name;
}	t_category;

typedef struct s_command
{
    const char          *name;
    const t_category    *category;
    void (*process_func)(const t_command *cmd, int argc, char **argv);
}	t_command;

void free_input(void *content);
void fatal_error(t_context *ctx, const char *s1, const char *s2, const char *s3, void (*free_ctx)(t_context *ctx));
void print_error(const char *s1, const char *s2, const char *s3);
ssize_t read_from_input(t_input *input, void* buffer, size_t nbytes);
int get_fd(t_context *ctx, const char *file, int default_fd, bool is_output);
uint32_t rotate_left_28(uint32_t x, size_t n);
uint8_t hex_to_value(char c);

t_context *parse_digest(const t_command *cmd, int argc, char **argv);
void process_digest(const t_command *cmd, t_context *ctx);

t_context *parse_des(const t_command *cmd, int argc, char **argv);
uint64_t des(uint64_t input, uint64_t *subkeys, bool decrypt_mode);
uint8_t *generate_random_bytes(const t_command *cmd, t_context *ctx, size_t nbytes);
char *ask_password(const t_command *cmd, t_context *ctx);
void des_print_mode(t_context *ctx, bool show_iv);
uint64_t *key_scheduler(uint64_t key);

void clear_digest_ctx(t_context *ctx);
void clear_base64_ctx(t_context *ctx);
void clear_des_ctx(t_context *ctx);

#endif
