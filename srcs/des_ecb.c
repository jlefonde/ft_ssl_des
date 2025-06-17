#include "ssl.h"

void process_des_ecb(const t_command *cmd, int argc, char **argv)
{   
    t_context *ctx = parse_des(cmd, argc, argv);

    if (!prepare_des(cmd, ctx, false))
    {
        clear_des_ctx(ctx);
        return;
    }

    size_t remaining = ctx->des.buffer.bytes_read;
    while ((ctx->des.buffer.bytes_read = read_from_input(&ctx->des.in, ctx->des.buffer.in + remaining, BASE64_BUFFER_SIZE - remaining)) > 0)
    {
        ctx->des.buffer.bytes_read += remaining;

        printf("BUFFER: ");
        for (int i = 0; i < ctx->des.buffer.bytes_read; i++)
            printf("%02x ", ctx->des.buffer.in[i]);
        printf("\n");

        printf("BUFFER + 8: ");
        for (int i = 0; i < ctx->des.buffer.bytes_read - 8; i++)
            printf("%02x ", (ctx->des.buffer.in + 8)[i]);
        printf("\n");

        if (ctx->des.decrypt_mode && ctx->des.base64_mode)
        {
            // Only decode the newly read data, not the remaining bytes
            if (remaining > 0 && ctx->des.buffer.bytes_read > remaining) {
                // Save the already decoded data
                uint8_t *already_decoded = malloc(remaining);
                if (!already_decoded)
                    fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_des_ctx);
                
                ft_memcpy(already_decoded, ctx->des.buffer.in, remaining);
                
                // Decode only the new portion
                uint8_t *new_data = malloc(ctx->des.buffer.bytes_read - remaining);
                if (!new_data) {
                    free(already_decoded);
                    fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_des_ctx);
                }
                
                ft_memcpy(new_data, ctx->des.buffer.in + remaining, ctx->des.buffer.bytes_read - remaining);
                
                // Adjust bytes_read to reflect only the new data being decoded
                ssize_t new_bytes = ctx->des.buffer.bytes_read - remaining;
                uint8_t *decoded_new = decode_base64_buffer(cmd, new_data, &new_bytes);
                if (!decoded_new) {
                    free(already_decoded);
                    fatal_error(ctx, NULL, NULL, NULL, clear_des_ctx);
                }
                
                // Combine already decoded data with newly decoded data
                uint8_t *combined = malloc(remaining + new_bytes);
                if (!combined) {
                    free(already_decoded);
                    free(decoded_new);
                    fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_des_ctx);
                }
                
                ft_memcpy(combined, already_decoded, remaining);
                ft_memcpy(combined + remaining, decoded_new, new_bytes);
                
                free(already_decoded);
                free(decoded_new);
                free(ctx->des.buffer.in);
                
                ctx->des.buffer.in = combined;
                ctx->des.buffer.bytes_read = remaining + new_bytes;
            } else {
                // No remaining data, decode everything
                ctx->des.buffer.in = decode_base64_buffer(cmd, ctx->des.buffer.in, &ctx->des.buffer.bytes_read);
                if (!ctx->des.buffer.in)
                    fatal_error(ctx, NULL, NULL, NULL, clear_des_ctx);
            }
        }

        ctx->des.buffer.total_bytes_read += ctx->des.buffer.bytes_read;

        if (!ctx->des.decrypt_mode && ctx->des.prepend_salt)
            prepend_salt_to_output(ctx);

        if ((ctx->des.buffer.out_pos + 8) >= BASE64_BUFFER_SIZE)
            write_output(ctx->des.out_fd, ctx->des.buffer.out, &ctx->des.buffer.out_pos);

        for (int i = 0; i < ctx->des.buffer.bytes_read; i += 8)
        {
            uint8_t block[8];
            ft_memcpy(block, ctx->des.buffer.in + i, 8);

            if (!ctx->des.decrypt_mode)
                pkcs7(block, ctx->des.buffer.bytes_read - i);

            uint64_t cipher = des(bytes_to_uint64(block), ctx->des.subkeys, ctx->des.decrypt_mode);
            append_cipher_to_output(cipher, ctx->des.buffer.out, &ctx->des.buffer.out_pos);
        }

        if (ctx->des.buffer.bytes_read < BASE64_BUFFER_SIZE)
            break;

        remaining = 0;
    }

    if (!ctx->des.decrypt_mode && ((ctx->des.buffer.total_bytes_read % 8) == 0))
        add_padding_block(ctx, ctx->des.buffer.out, &ctx->des.buffer.out_pos);

    if (ctx->des.decrypt_mode)
        remove_padding(cmd, ctx, ctx->des.buffer.out, &ctx->des.buffer.out_pos);

    if (ctx->des.buffer.out_pos > 0)
        write_output(ctx->des.out_fd, ctx->des.buffer.out, &ctx->des.buffer.out_pos);

    if (ctx->des.buffer.bytes_read == -1)
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_base64_ctx);

    clear_des_ctx(ctx);
}
