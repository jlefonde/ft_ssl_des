#include "ssl.h"

// openssl enc -des-ecb -pbkdf2 -provider default -provider legacy -P
// openssl enc -des-ecb -pbkdf2 -provider default -provider legacy -pass pass:test -S "ABC" -P
void process_des_ecb(const t_command *cmd, int argc, char **argv)
{   
    t_context *ctx = parse_des(cmd, argc, argv);

    if (ctx->des.iv)
        write(STDERR_FILENO, "warning: iv not used by this cipher\n", 36);

    if (!ctx->des.password && !ctx->des.key)
        ctx->des.password = ask_password(cmd, ctx);

    if (!ctx->des.salt)
        ctx->des.salt = generate_random_bytes(cmd, ctx, 8);

    if (!ctx->des.key)
        ctx->des.key = pbkdf2(hmac_sha256, 32, ctx->des.password, ft_strlen(ctx->des.password),
            ctx->des.salt, DES_SALT_LEN, DES_PBKDF_ITR, DES_DK_LEN);

    if (ctx->des.print_mode)
    {
        des_print_mode(ctx, false);
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

        if ((out_pos + 8) >= BUFFER_SIZE)
            write_output(ctx->des.out, buffer_out, &out_pos);

        for (int i = 0; i < bytes_read; i += 8)
        {
            uint8_t block[8];
            ft_memcpy(block, buffer_in + i, 8);

            int remaining_bytes = bytes_read - i;
            if (remaining_bytes < 8)
            {
                int npad = 8 - remaining_bytes;
                ft_memset(block + remaining_bytes, npad, npad);
            }

            uint64_t cipher = des(bytes_to_uint64(block), subkeys, ctx->des.decrypt_mode);
            // printf("%lX", cipher);
            for (int j = 0; j < 8; j++)
                buffer_out[out_pos++] = (cipher >> (56 - (j * 8))) & 0xFF;
        }

        if (bytes_read < BUFFER_SIZE)
            break;
    }

    if ((total_bytes_read % 8) == 0)
    {
        uint8_t block[8];
        ft_memset(block, 0x08, 8);

        uint64_t cipher = des(bytes_to_uint64(block), subkeys, ctx->des.decrypt_mode);
        // printf("%lX", cipher);
        for (int j = 0; j < 8; j++)
            buffer_out[out_pos++] = (cipher >> (56 - (j * 8))) & 0xFF;
    }

    if (out_pos > 0)
        write_output(ctx->des.out, buffer_out, &out_pos);

    free(subkeys);
    if (bytes_read == -1)
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_base64_ctx);

    clear_des_ctx(ctx);
}
