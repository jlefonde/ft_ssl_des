# ifndef DES_H
#  define DES_H

# include "ssl.h"

# define PASSWORD_MAX_LEN 128
# define DES_SALT_LEN 8
# define DES_KEY_LEN 8
# define DES3_KEY_LEN 24
# define DES_IV_LEN 8
# define DES_PBKDF_ITR 10000
# define DES_BUFFER_SIZE 3072

typedef struct s_command t_command;
typedef union u_context t_context;

void process_des_cbc(const t_command *cmd, int argc, char **argv);
void process_des_ecb(const t_command *cmd, int argc, char **argv);
void process_des_cfb(const t_command *cmd, int argc, char **argv);
void process_des_ofb(const t_command *cmd, int argc, char **argv);
void process_des3_cbc(const t_command *cmd, int argc, char **argv);
void process_des3_ecb(const t_command *cmd, int argc, char **argv);
void process_des3_cfb(const t_command *cmd, int argc, char **argv);
void process_des3_ofb(const t_command *cmd, int argc, char **argv);

void process_des_ecb_block(t_context *ctx, uint8_t *in_block, size_t remaining_bytes, size_t bytes_to_append);
void finalize_des_ecb_mode(const t_command *cmd, t_context *context);

void init_des_cbc_mode(t_context *ctx);
void process_des_cbc_block(t_context *ctx, uint8_t *in_block, size_t remaining_bytes, size_t bytes_to_append);
void finalize_des_cbc_mode(const t_command *cmd, t_context *context);

void init_des_cfb_mode(t_context *ctx);
void process_des_cfb_block(t_context *ctx, uint8_t *in_block, size_t remaining_bytes, size_t bytes_to_append);

void init_des_ofb_mode(t_context *ctx);
void process_des_ofb_block(t_context *ctx, uint8_t *in_block, size_t remaining_bytes, size_t bytes_to_append);

int prepare_des(const t_command *cmd, t_context *ctx, bool iv_required, size_t key_len);
uint8_t *decode_base64_buffer(const t_command *cmd, t_context *ctx, uint8_t *buffer, size_t buffer_size, 
    size_t *decoded_size, bool is_last_chunk);
void prepend_salt_to_output(t_context *ctx, uint8_t *buffer, size_t *buffer_pos);
void append_to_output(uint64_t cipher, uint8_t *buffer, size_t *buffer_pos, size_t nbytes);
size_t process_des_input_chunk(const t_command *cmd, t_context *ctx, uint8_t *des_buffer, size_t *des_buffer_size,
    bool *is_last_chunk);
void handle_remainder(uint8_t *buffer, size_t *buffer_size, uint8_t *remainder, size_t *remainder_size, size_t *offset);
void prepare_des_buffer(const t_command *cmd, t_context *ctx, uint8_t *des_buffer, size_t *des_buffer_size, 
    bool is_last_chunk);
size_t align_buffer(t_context *ctx, uint8_t *des_buffer, size_t des_buffer_size, bool is_last_chunk);
void pkcs7(uint8_t *block, ssize_t remaining_bytes);
void remove_padding(const t_command *cmd, t_context *ctx, uint8_t *out_buffer, size_t *out_pos);
void write_des_output(const t_command *cmd, t_context *ctx);
t_context *parse_des(const t_command *cmd, int argc, char **argv, size_t hex_len);
uint64_t des(uint64_t block, uint64_t *subkeys, bool decrypt_mode);
void clear_des_ctx(t_context *ctx);

# endif