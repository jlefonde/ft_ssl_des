#include "ssl.h"

void prepend_salt_to_output(t_context *ctx)
{
    write(ctx->des.out, "Salted__", 8);
    write(ctx->des.out, ctx->des.salt, 8);
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

void assign_derived_key(const t_command *cmd, t_context *ctx, uint8_t **dest, uint8_t *dk, size_t n)
{
    *dest = malloc(n);
    if (!*dest)
    {
        free(dk);
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_des_ctx);
    }

    ft_memcpy(*dest, dk, n);
}

int prepare_des(const t_command *cmd, t_context *ctx, bool iv_required)
{
    if (ctx->des.iv && !iv_required)
        write(STDERR_FILENO, "warning: iv not used by this cipher\n", 36);

    if (ctx->des.password && !ctx->des.key && !ctx->des.salt)
        ctx->des.prepend_salt = true;

    if (!ctx->des.password && !ctx->des.key)
        ctx->des.password = ask_password(cmd, ctx);

    if (!ctx->des.salt && !ctx->des.key)
    {
        ctx->des.salt = generate_random_bytes(cmd, ctx, 8);
        ctx->des.prepend_salt = true;
    }

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

    return (1);
}

void add_padding_block(t_context *ctx, uint64_t *subkeys, uint8_t *buffer_out, size_t *out_pos)
{
    uint8_t block[8];

    if (ctx->des.prepend_salt)
        prepend_salt_to_output(ctx);

    pkcs7(block, 0);

    uint64_t cipher = des(bytes_to_uint64(block), subkeys, ctx->des.decrypt_mode);
    append_cipher_to_output(cipher, buffer_out, out_pos);
}

void remove_padding(const t_command *cmd, t_context *ctx, uint8_t *buffer_out, size_t *out_pos)
{
    uint8_t last_byte = buffer_out[*out_pos - 1];
    if (last_byte < 1 || last_byte > 8)
        fatal_error(ctx, cmd->name, "Corrupted data", NULL, clear_des_ctx);

    for (int i = *out_pos - last_byte; i < *out_pos; i++)
    {
        if (buffer_out[i] != last_byte)
            fatal_error(ctx, cmd->name, "Corrupted data", NULL, clear_des_ctx);
    }

    *out_pos -= last_byte;
}

void process_des_ecb(const t_command *cmd, int argc, char **argv)
{   
    t_context *ctx = parse_des(cmd, argc, argv);

    if (!prepare_des(cmd, ctx, false))
    {
        clear_des_ctx(ctx);
        return;
    }

    uint64_t key = bytes_to_uint64(ctx->des.key);
    uint64_t *subkeys = key_scheduler(key);
    if (!subkeys)
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_des_ctx);

    ssize_t bytes_read = 0;
    ssize_t total_bytes_read = 0;
    uint8_t buffer_in[BUFFER_SIZE];
    uint8_t buffer_out[BUFFER_SIZE];
    size_t out_pos = 0;

    while ((bytes_read = read_from_input(&ctx->des.in, buffer_in, BUFFER_SIZE)) > 0)
    {
        total_bytes_read += bytes_read;

        if (ctx->des.prepend_salt)
            prepend_salt_to_output(ctx);

        if ((out_pos + 8) >= BUFFER_SIZE)
            write_output(ctx->des.out, buffer_out, &out_pos);

        for (int i = 0; i < bytes_read; i += 8)
        {
            uint8_t block[8];
            ft_memcpy(block, buffer_in + i, 8);

            if (!ctx->des.decrypt_mode)
                pkcs7(block, bytes_read - i);

            uint64_t cipher = des(bytes_to_uint64(block), subkeys, ctx->des.decrypt_mode);
            append_cipher_to_output(cipher, buffer_out, &out_pos);
        }

        if (bytes_read < BUFFER_SIZE)
            break;
    }

    if (!ctx->des.decrypt_mode && ((total_bytes_read % 8) == 0))
        add_padding_block(ctx, subkeys, buffer_out, &out_pos);

    free(subkeys);

    if (ctx->des.decrypt_mode)
        remove_padding(cmd, ctx, buffer_out, &out_pos);

    if (out_pos > 0)
        write_output(ctx->des.out, buffer_out, &out_pos);

    if (bytes_read == -1)
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_base64_ctx);

    clear_des_ctx(ctx);
}
