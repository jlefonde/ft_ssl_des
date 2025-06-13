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
        des_print_mode(ctx, false);
    else
    {
        uint64_t key = bytes_to_uint64(ctx->des.key);
        uint64_t *subkeys = key_scheduler(key);
        if (!subkeys)
            fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_des_ctx);
    
        ssize_t bytes_read = 0;
        uint8_t buffer_in[BUFFER_SIZE];
        uint8_t buffer_out[BUFFER_SIZE / 8];
        size_t out_pos = 0;

        t_input input;
        input.fd = ctx->des.in;
        input.type = ctx->des.in == STDIN_FILENO ? INPUT_STDIN : INPUT_FILE;
        input.data_pos = -1;

        while ((bytes_read = read_from_input(&input, buffer_in, BUFFER_SIZE)) > 0)
        {
            if (out_pos == BUFFER_SIZE / 8)
            {
                write(ctx->des.out, buffer_out, out_pos);
                out_pos = 0;
                ft_memset(buffer_out, 0x00, BUFFER_SIZE / 8);
            }

            for (int i = 0; i < bytes_read; i += 8)
            {
                uint64_t block = bytes_to_uint64(buffer_in + i);

                uint64_t cipher = des(block, subkeys, ctx->des.decrypt_mode);

                for (int j = 0; j < 8; j++)
                    buffer_out[out_pos++] = (cipher >> (56 - (j * 8))) & 0xFF;
            }

            if (bytes_read < BUFFER_SIZE)
                break;
        }

        if (out_pos > 0)
            write(ctx->des.out, buffer_out, out_pos);

        if (bytes_read == -1)
            ;
        
        free(subkeys);
    }

    clear_des_ctx(ctx);
}
