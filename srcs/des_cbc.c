#include "ssl.h"

void process_des_cbc(const t_command *cmd, int argc, char **argv)
{   
    t_context *ctx = parse_des(cmd, argc, argv);

    if (!prepare_des(cmd, ctx, true))
    {
        clear_des_ctx(ctx);
        return;
    }

    bool first_block = true;

    size_t remaining = ctx->des.buffer.bytes_read;
    uint64_t cipher;
    while ((ctx->des.buffer.bytes_read = read_from_input(&ctx->des.in, ctx->des.buffer.in + remaining, BASE64_BUFFER_SIZE - remaining)) > 0)
    {
        ctx->des.buffer.bytes_read += remaining;

        if (ctx->des.decrypt_mode && ctx->des.base64_mode)
        {
            // Decode Base64
        }

        ctx->des.buffer.total_bytes_read += ctx->des.buffer.bytes_read;

        if (!ctx->des.decrypt_mode && ctx->des.prepend_salt)
            prepend_salt_to_output(ctx);

        if ((ctx->des.buffer.out_pos + 8) >= BASE64_BUFFER_SIZE)
            write_des_output(cmd, ctx);

        for (int i = 0; i < ctx->des.buffer.bytes_read; i += 8)
        {
            uint8_t block[8];
            ft_memcpy(block, ctx->des.buffer.in + i, 8);

            if (!ctx->des.decrypt_mode)
            {
                pkcs7(block, ctx->des.buffer.bytes_read - i);

                for (int j = 0; j < 8; j++)
                {
                    if (first_block)
                        block[j] ^= ctx->des.iv[j];
                    else
                        block[j] ^= (cipher >> (j * 8)) & 0xFF;
                }

                cipher = des(bytes_to_uint64(block), ctx->des.subkeys, ctx->des.decrypt_mode);
                append_cipher_to_output(cipher, ctx->des.buffer.out, &ctx->des.buffer.out_pos);
            }
            else
            {
                uint64_t current_cipher = bytes_to_uint64(block);

                uint64_t decrypted = des(current_cipher, ctx->des.subkeys, ctx->des.decrypt_mode);

                for (int j = 0; j < 8; j++)
                {
                    if (first_block)
                        block[j] = ((decrypted >> (56 - (j * 8))) & 0xFF) ^ ctx->des.iv[j];
                    else
                        block[j] = ((decrypted >> (56 - (j * 8))) & 0xFF) ^ ((cipher >> (56 - (j * 8))) & 0xFF);
                }

                cipher = current_cipher;
                append_cipher_to_output(bytes_to_uint64(block), ctx->des.buffer.out, &ctx->des.buffer.out_pos);
            }

            first_block = false;
        }

        if (ctx->des.buffer.bytes_read < BASE64_BUFFER_SIZE)
            break;

        remaining = 0;
    }

    if (!ctx->des.decrypt_mode && ((ctx->des.buffer.total_bytes_read % 8) == 0))
        add_padding(ctx, ctx->des.buffer.out, &ctx->des.buffer.out_pos);

    if (ctx->des.decrypt_mode)
        remove_padding(cmd, ctx, ctx->des.buffer.out, &ctx->des.buffer.out_pos);

    if (ctx->des.buffer.out_pos > 0)
        write_des_output(cmd, ctx);

    if (ctx->des.buffer.bytes_read == -1)
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_base64_ctx);

    clear_des_ctx(ctx);
}
