#include "ssl.h"

static const size_t g_ip[64] = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
};

static const size_t g_fp[64] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25
};

static const size_t g_exp[48] = {
    32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,  8,  9, 10, 11, 
    12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
};

static const size_t g_p[32] = {
    16, 7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5,  18, 31, 10,
    2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6,  22, 11,  4, 25
};

static const size_t g_pc1[56] = {
    57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
};

static const size_t g_pc2[48] = {
    14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

static const uint8_t g_sbox[8][4][16] = {
    { 
        { 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7 },
        {  0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8 },
        {  4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0 },
        { 15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13 }
    },
    {
        { 15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10 },
        {  3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5 },
        {  0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15 },
        { 13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9 }
    },
    {
        { 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8 },
        { 13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1 },
        { 13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7 },
        {  1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 }
    },
    {
        {  7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15 },
        { 13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9 },
        { 10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4 },
        {  3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14 }
    },
    {
        {  2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9 },
        { 14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6 },
        {  4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14 },
        { 11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3 }
    },
    {
        { 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11 },
        { 10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8, },
        {  9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6, },
        {  4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13 }
    },
    {
        {  4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1 },
        { 13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6 },
        {  1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2 },
        {  6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12 }
    },
    {
        { 13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7 },
        {  1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2 },
        {  7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8 },
        {  2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 }
    }
};

static const size_t g_rot[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

void clear_des_ctx(t_context *ctx)
{
    free(ctx->des.password);
    free(ctx->des.key);
    free(ctx->des.salt);
    free(ctx->des.iv);
    free(ctx->des.subkeys);
    free(ctx->des.buffer.in);
    free(ctx->des.buffer.out);
    if (ctx->des.in.fd > 1)
        close(ctx->des.in.fd);
    if (ctx->des.out_fd > 1)
        close(ctx->des.out_fd);
    free(ctx);
}

static void print_hex_str(uint8_t *hex, const char *label)
{
    ft_printf("%s=", label);
    for (int i = 0; i < 8; i++)
        ft_printf("%02X", hex[i]);
    ft_printf("\n");
}

static uint8_t *generate_random_bytes(const t_command *cmd, t_context *ctx, size_t nbytes)
{
    uint8_t * buffer = malloc(nbytes);
    if (!buffer)
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_des_ctx);

    int urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd == -1)
    {
        free(buffer);
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_des_ctx);
    }

    ssize_t bytes_read = read(urandom_fd, buffer, nbytes);
    close(urandom_fd);
    if (bytes_read == -1)
    {
        free(buffer);
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_des_ctx);
    }

    return (buffer);
}

static void des_print_mode(t_context *ctx, bool show_iv)
{
    print_hex_str(ctx->des.key, "key");
    print_hex_str(ctx->des.salt, "salt");
    
    if (show_iv)
        print_hex_str(ctx->des.iv, "iv");
}

static uint8_t parse_hex_digit(const t_command *cmd, t_context *ctx, char c, uint8_t *hex)
{
    uint8_t hex_value = hex_to_value(c);
    if (hex_value > 15)
    {
        free(hex);
        fatal_error(ctx, cmd->name, "Invalid hex value", NULL, clear_des_ctx);
    }
    return (hex_value);
}

static uint8_t *parse_hex_str(const t_command *cmd, t_context *ctx, const char *hex_str)
{
    size_t hex_str_len = ft_strlen(hex_str);

    if (hex_str_len < 16)
        write(STDERR_FILENO, "hex string is too short, padding with zero bytes to length\n", 59);
    else if (hex_str_len > 16)
    {
        write(STDERR_FILENO, "hex string is too long, ignoring excess\n", 40);
        hex_str_len = 16;
    }

    uint8_t *hex = malloc(8);
    if (!hex)
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_des_ctx);

    ft_memset(hex, 0x00, 8);

    int i = 0;
    for (size_t j = 0; j < hex_str_len; j += 2, i++)
    {
        hex[i] = parse_hex_digit(cmd, ctx, hex_str[j], hex);
        hex[i] <<= 4;
        if ((j + 1) < hex_str_len)
            hex[i] |= parse_hex_digit(cmd, ctx, hex_str[j + 1], hex);
    }

    return (hex);
}

static char *ask_password(const t_command *cmd, t_context *ctx, bool skip_verify)
{
    char *password = malloc(PASSWORD_MAX_LEN + 2);
    if (!password)
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_des_ctx);

    char *cmd_name = ft_strmap(cmd->name, ft_toupper);
    ft_printf("enter %s %scryption password: ", cmd_name, ctx->des.decrypt_mode ? "de" : "en");

    if (!readpassphrase("", password, PASSWORD_MAX_LEN + 2, RPP_REQUIRE_TTY))
    {
        free(password);
        free(cmd_name);
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_des_ctx);
    }

    if (!skip_verify)
    {
        char password_verify[PASSWORD_MAX_LEN + 2];
        ft_printf("Verifying - enter %s encryption password: ", cmd_name);
        free(cmd_name);

        if (!readpassphrase("", password_verify, PASSWORD_MAX_LEN + 2, RPP_REQUIRE_TTY))
        {
            free(password);
            fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_des_ctx);
        }

        if (ft_strcmp(password, password_verify) != 0)
        {
            free(password);
            fatal_error(ctx, cmd->name, "Password mismatch", NULL, clear_des_ctx);
        }
    }

    size_t password_len = ft_strlen(password);
    if (password_len > PASSWORD_MAX_LEN)
    {
        free(password);
        fatal_error(ctx, cmd->name, "Password exceeds max length", NULL, clear_des_ctx);
    }
    else if (!password_len)
        fatal_error(ctx, NULL, NULL, NULL, clear_des_ctx);

    return (password);
}

static void assign_derived_key(const t_command *cmd, t_context *ctx, uint8_t **dest, uint8_t *dk, size_t n)
{
    *dest = malloc(n);
    if (!*dest)
    {
        free(dk);
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_des_ctx);
    }

    ft_memcpy(*dest, dk, n);
}

void decode_partial_base64_buffer(const t_command *cmd, t_context *ctx, size_t remaining)
{
    if (remaining == 0)
    {
        printf("BR: %ld\n", ctx->des.buffer.bytes_read);
        ctx->des.buffer.in = decode_base64_buffer(cmd, ctx->des.buffer.in, &ctx->des.buffer.bytes_read);
        if (!ctx->des.buffer.in)
            fatal_error(ctx, NULL, NULL, NULL, clear_des_ctx);
        return;
    }

    uint8_t *encoded_buffer = malloc(ctx->des.buffer.bytes_read - remaining);
    if (!encoded_buffer)
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_des_ctx);
    
    ssize_t encoded_buffer_size = ctx->des.buffer.bytes_read - remaining;
    ft_memcpy(encoded_buffer, ctx->des.buffer.in + remaining, encoded_buffer_size);

    uint8_t *decoded_buffer = decode_base64_buffer(cmd, encoded_buffer, &encoded_buffer_size);
    if (!decoded_buffer)
    {
        free(encoded_buffer);
        fatal_error(ctx, NULL, NULL, NULL, clear_des_ctx);
    }

    ft_memcpy(ctx->des.buffer.in + remaining, decoded_buffer, encoded_buffer_size);
    free(decoded_buffer);

    ctx->des.buffer.bytes_read = remaining + encoded_buffer_size;
}

uint8_t *decode_base64_buffer(const t_command *cmd, uint8_t *buffer, ssize_t *bytes_read)
{
    size_t decoded_size = 0;

    uint8_t *decoded_buffer = decode_base64_flag(cmd, buffer, *bytes_read, &decoded_size);
    if (!decoded_buffer)
    {
        printf("HERE2");
        return (NULL);
    }

    *bytes_read = decoded_size;

    free(buffer);
    return (decoded_buffer);
}

static uint8_t *read_salt(const t_command *cmd, t_context *ctx)
{
    uint8_t *salted_header; 
    size_t buffer_size;

    if (ctx->des.base64_mode)
    {
        buffer_size = 32;
        salted_header = malloc(buffer_size);
        if (!salted_header)
            fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_des_ctx);
    }
    else
    {
        buffer_size = 16;
        salted_header = malloc(buffer_size);
        if (!salted_header)
            fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_des_ctx);        
    }

    ssize_t bytes_read = read(ctx->des.in.fd, salted_header, buffer_size);
    if (bytes_read == -1)
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_des_ctx);

    if (ctx->des.base64_mode)
    {
        salted_header = decode_base64_buffer(cmd, salted_header, &bytes_read);
        if (!salted_header)
            fatal_error(ctx, NULL, NULL, NULL, clear_des_ctx);
    }

    if (ft_memcmp(salted_header, "Salted__", 8) != 0)
        fatal_error(ctx, cmd->name, "Bad magic number", NULL, clear_des_ctx);

    if (bytes_read < 16)
        fatal_error(ctx, cmd->name, "Error reading input file", NULL, clear_des_ctx);

    uint8_t *salt = malloc(8);
    if (!salt)
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_des_ctx);
    
    size_t remaining = bytes_read - 16;
    if (remaining > 0)
    {
        ft_memcpy(ctx->des.buffer.in, salted_header + 16, remaining);
        ctx->des.buffer.bytes_read = remaining;
    }

    return (ft_memcpy(salt, salted_header + 8, 8));
}

static uint64_t permute(uint64_t block, size_t block_size, const size_t *p_arr, size_t out_size)
{
    uint64_t permutation = 0;

    for (size_t i = 0; i < out_size; i++)
    {
        size_t block_bit_pos = p_arr[i] - 1;

        if ((block >> (block_size - 1 - block_bit_pos)) & 1)
            permutation |= ((uint64_t)1 << (out_size - 1 - i));
    }

    return (permutation);
}

static uint64_t *key_scheduler(uint64_t key)
{
    uint64_t *subkeys = malloc(16 * sizeof(uint64_t));
    if (!subkeys)
        return (NULL);

    uint64_t pc1 = permute(key, 64, g_pc1, 56);

    uint32_t left_half = (pc1 >> 28) & 0xFFFFFFF;
    uint32_t right_half = pc1 & 0xFFFFFFF;

    for (int i = 0; i < 16; i++)
    {
        left_half = rotate_left_28(left_half, g_rot[i]);
        right_half = rotate_left_28(right_half, g_rot[i]);

        uint64_t combined = ((uint64_t)left_half << 28) | right_half;
        subkeys[i] = permute(combined, 56, g_pc2, 48);
    }

    return (subkeys);
}

int prepare_des(const t_command *cmd, t_context *ctx, bool iv_required)
{
    ctx->des.buffer.in = malloc(BASE64_BUFFER_SIZE);
    if (!ctx->des.buffer.in)
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_des_ctx);

    ctx->des.buffer.out = malloc(BASE64_BUFFER_SIZE * 2);
    if (!ctx->des.buffer.out)
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_des_ctx);

    if (ctx->des.iv && !iv_required)
        write(STDERR_FILENO, "warning: iv not used by this cipher\n", 36);

    if (ctx->des.password && !ctx->des.key && !ctx->des.salt)
        ctx->des.prepend_salt = true;

    if (!ctx->des.password && !ctx->des.key)
        ctx->des.password = ask_password(cmd, ctx, ctx->des.decrypt_mode);

    if (!ctx->des.salt && !ctx->des.key)
    {
        if (!ctx->des.decrypt_mode)
            ctx->des.salt = generate_random_bytes(cmd, ctx, 8);
        ctx->des.prepend_salt = true;
    }

    if (ctx->des.decrypt_mode && ctx->des.prepend_salt)
        ctx->des.salt = read_salt(cmd, ctx);

    if (iv_required && !ctx->des.iv && !ctx->des.password && ctx->des.key)
        fatal_error(ctx, cmd->name, "iv undefined", NULL, clear_des_ctx);

    if (ctx->des.password && ctx->des.salt)
    {
        uint8_t *dk = pbkdf2(hmac_sha256, 32, ctx->des.password, ft_strlen(ctx->des.password),
            ctx->des.salt, DES_SALT_LEN, DES_PBKDF_ITR, DES_KEY_LEN + DES_IV_LEN);

        if (!ctx->des.key)
            assign_derived_key(cmd, ctx, &ctx->des.key, dk, DES_KEY_LEN);

        if (!ctx->des.iv && iv_required)
            assign_derived_key(cmd, ctx, &ctx->des.iv, dk + DES_KEY_LEN, DES_IV_LEN);

        free(dk);
    }

    if (ctx->des.print_mode)
    {
        if (!ctx->des.salt)
            ctx->des.salt = generate_random_bytes(cmd, ctx, DES_SALT_LEN);
        des_print_mode(ctx, iv_required);
        return (0);
    }

    ctx->des.subkeys = key_scheduler(bytes_to_uint64(ctx->des.key));
    if (!ctx->des.subkeys)
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_des_ctx);

    return (1);
}

void prepend_salt_to_output(t_context *ctx)
{
    write(ctx->des.out_fd, "Salted__", 8);
    write(ctx->des.out_fd, ctx->des.salt, 8);
    ctx->des.prepend_salt = false;
}

void append_cipher_to_output(uint64_t cipher, uint8_t *buffer, size_t *buffer_pos)
{
    for (int i = 0; i < 8; i++)
        buffer[(*buffer_pos)++] = (cipher >> (56 - (i * 8))) & 0xFF;
}

void pkcs7(uint8_t *block, ssize_t remaining_bytes)
{
    if (remaining_bytes < 8)
    {
        int npad = 8 - remaining_bytes;
        ft_memset(block + remaining_bytes, npad, npad);
    }
}

void add_padding_block(t_context *ctx, uint8_t *out_buffer, size_t *out_pos)
{
    uint8_t block[8];

    if (ctx->des.prepend_salt)
        prepend_salt_to_output(ctx);

    pkcs7(block, 0);

    uint64_t cipher = des(bytes_to_uint64(block), ctx->des.subkeys, ctx->des.decrypt_mode);
    append_cipher_to_output(cipher, out_buffer, out_pos);
}

void remove_padding(const t_command *cmd, t_context *ctx, uint8_t *out_buffer, size_t *out_pos)
{
    uint8_t last_byte = out_buffer[*out_pos - 1];
    if (last_byte < 1 || last_byte > 8)
        fatal_error(ctx, cmd->name, "Corrupted data", NULL, clear_des_ctx);

    for (size_t i = *out_pos - last_byte; i < *out_pos; i++)
    {
        if (out_buffer[i] != last_byte)
            fatal_error(ctx, cmd->name, "Corrupted data", NULL, clear_des_ctx);
    }

    *out_pos -= last_byte;
}

void write_des_output(const t_command *cmd, t_context *ctx)
{
    if (!ctx->des.decrypt_mode && ctx->des.base64_mode)
    {
        size_t encoded_size = 0;
        uint8_t *encoded_buffer = encode_base64_flag(cmd, ctx->des.buffer.out, ctx->des.buffer.out_pos, &encoded_size);
        if (!encoded_buffer)
            fatal_error(ctx, NULL, NULL, NULL, clear_des_ctx);
        free(ctx->des.buffer.out);
        ctx->des.buffer.out = encoded_buffer;
        ctx->des.buffer.out_pos = encoded_size;
    }

    write_output(ctx->des.out_fd, ctx->des.buffer.out, &ctx->des.buffer.out_pos);
}

t_context *parse_des(const t_command *cmd, int argc, char **argv)
{   
    t_context *ctx = (t_context *)malloc(sizeof(t_context));
    if (!ctx)
    {
        print_error(cmd->name, strerror(errno), NULL);
        exit(EXIT_FAILURE);
    }

    ctx->des.in.fd = STDIN_FILENO;
    ctx->des.out_fd = STDOUT_FILENO;
    ctx->des.key = NULL;
    ctx->des.password = NULL;
    ctx->des.salt = NULL;
    ctx->des.iv = NULL;
    ctx->des.subkeys = NULL;
    ctx->des.decrypt_mode = false;
    ctx->des.base64_mode = false;
    ctx->des.print_mode = false;
    ctx->des.prepend_salt = false;
    ctx->des.buffer.in = NULL;
    ctx->des.buffer.out = NULL;
    ctx->des.buffer.bytes_read = 0;
    ctx->des.buffer.total_bytes_read = 0;
    ctx->des.buffer.out_pos = 0;

    char *in_file = NULL;
    char *out_file = NULL;
    bool in_mode = false;
    bool out_mode = false;
    bool key_mode = false;
    bool password_mode = false;
    bool salt_mode = false;
    bool iv_mode = false;
    for (int i = 2; i < argc; ++i)
    {
        bool input_mode = (in_mode || out_mode);

        if (!input_mode && argv[i][0] == '-')
        {
            if (ft_strcmp(argv[i], "-d") == 0)
                ctx->des.decrypt_mode = true;
            else if (ft_strcmp(argv[i], "-e") == 0)
                ctx->des.decrypt_mode = false;
            else if (ft_strcmp(argv[i], "-a") == 0)
                ctx->des.base64_mode = true;
            else if (ft_strcmp(argv[i], "-P") == 0)
                ctx->des.print_mode = true;
            else if (ft_strcmp(argv[i], "-i") == 0)
                in_mode = true;
            else if (ft_strcmp(argv[i], "-o") == 0)
                out_mode = true;
            else if (ft_strcmp(argv[i], "-p") == 0)
                password_mode = true;
            else if (ft_strcmp(argv[i], "-k") == 0)
                key_mode = true;
            else if (ft_strcmp(argv[i], "-s") == 0)
                salt_mode = true;
            else if (ft_strcmp(argv[i], "-v") == 0)
                iv_mode = true;
            else
                fatal_error(ctx, cmd->name, argv[i], "Unknown option", clear_des_ctx);
        }
        else if (in_mode)
        {
            in_file = argv[i];
            in_mode = false;
        }
        else if (out_mode)
        {
            out_file = argv[i];
            out_mode = false;
        }
        else if (password_mode)
        {
            ctx->des.password = ft_strdup(argv[i]);
            password_mode = false;
        }
        else if (key_mode)
        {
            ctx->des.key = parse_hex_str(cmd, ctx, argv[i]);
            key_mode = false;
        }
        else if (salt_mode)
        {
            ctx->des.salt = parse_hex_str(cmd, ctx, argv[i]);
            salt_mode = false;
        }
        else if (iv_mode)
        {
            ctx->des.iv = parse_hex_str(cmd, ctx, argv[i]);
            iv_mode = false;
        }
        else
            fatal_error(ctx, cmd->name, "Extra option", argv[i], clear_des_ctx);
    }

    if (in_mode)
        fatal_error(ctx, cmd->name, NULL, "Option -i needs a value", clear_des_ctx);
    else if (out_mode)
        fatal_error(ctx, cmd->name, NULL, "Option -o needs a value", clear_des_ctx);
    else if (key_mode)
        fatal_error(ctx, cmd->name, NULL, "Option -k needs a value", clear_des_ctx);
    else if (password_mode)
        fatal_error(ctx, cmd->name, NULL, "Option -p needs a value", clear_des_ctx);
    else if (salt_mode)
        fatal_error(ctx, cmd->name, NULL, "Option -s needs a value", clear_des_ctx);
    else if (iv_mode)
        fatal_error(ctx, cmd->name, NULL, "Option -v needs a value", clear_des_ctx);

    ctx->des.in.fd = get_fd(in_file, ctx->des.in.fd, false);
    if (ctx->des.in.fd == -1)
        fatal_error(ctx, in_file, strerror(errno), NULL, clear_des_ctx);

    ctx->des.out_fd = get_fd(out_file, ctx->des.out_fd, true);
    if (ctx->des.out_fd == -1)
            fatal_error(ctx, out_file, strerror(errno), NULL, clear_des_ctx);

    ctx->des.in.type = (ctx->des.in.fd == STDIN_FILENO) ? INPUT_STDIN : INPUT_FILE;
    ctx->des.in.data_pos = -1;

    return (ctx);
}

static uint32_t substitute(uint64_t key_mix)
{
    uint32_t substitution = 0;

    for (int i = 0; i < 8; i++)
    {
        uint8_t s = (key_mix >> (48 - (i + 1) * 6)) & 0b00111111;

        uint8_t row = ((s >> 4) & 0b00000010) | (s & 1);
        uint8_t col = (s >> 1) & 0b00001111;

        substitution |= g_sbox[i][row][col];
        if (i < 7)
            substitution <<= 4;
    }

    return (substitution);
}

static uint32_t feistel(uint32_t half_block, uint64_t subkey)
{
    uint64_t expansion = permute(half_block, 32, g_exp, 48);

    uint32_t substitution = substitute(expansion ^ subkey);

    uint32_t permutation = permute(substitution, 32, g_p, 32);

    return (permutation);
}

uint64_t des(uint64_t block, uint64_t *subkeys, bool decrypt_mode)
{
    uint64_t ip = permute(block, 64, g_ip, 64);

    uint32_t left_half = (ip >> 32) & 0xFFFFFFFF;
    uint32_t right_half = ip & 0xFFFFFFFF;
    
    for (int i = 0; i < 16; i++)
    {
        size_t subkey_index = decrypt_mode ? 15 - i : i;
        uint32_t next_right_half = feistel(right_half, subkeys[subkey_index]) ^ left_half;

        left_half = right_half;
        right_half = next_right_half;
    }

    uint64_t combined = ((uint64_t)right_half << 32) | left_half;
        
    uint64_t fp = permute(combined, 64, g_fp, 64);

    return (fp);
}
