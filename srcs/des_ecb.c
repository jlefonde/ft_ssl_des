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
    size_t current_size = 0;
    size_t total_cipher_size = 0;
    while ((ctx->des.buffer.bytes_read = read_from_input(&ctx->des.in, ctx->des.buffer.in + remaining, BASE64_BUFFER_SIZE - remaining)) > 0)
    {
        printf("==================\n");
        ctx->des.buffer.bytes_read += remaining;
        current_size = ctx->des.buffer.bytes_read;

        printf("BYTES_READ: %zu\n", ctx->des.buffer.bytes_read);

        if (ctx->des.decrypt_mode && ctx->des.base64_mode)
            decode_partial_base64_buffer(cmd, ctx, remaining, &current_size);

        ctx->des.buffer.total_bytes_read += ctx->des.buffer.bytes_read;
        total_cipher_size += current_size;

        if (!ctx->des.decrypt_mode && ctx->des.prepend_salt)
            prepend_salt_to_output(ctx);

        if ((ctx->des.buffer.out_pos + 8) >= BASE64_BUFFER_SIZE)
            write_des_output(cmd, ctx);

        printf("CURRENT_SIZE: %zu\n", current_size);

        // TODO: the error when decoding base64 is due to the complete plaintext decoded that might not be a multiple of 8 bytes
        // meaning during this read iteration, it will cipher a block that is not complete since the rest is in the next read 
        for (int i = 0; i < current_size; i += 8)
        {
            uint8_t block[8];
            ft_memcpy(block, ctx->des.buffer.in + i, 8);

            if (!ctx->des.decrypt_mode)
                pkcs7(block, current_size - i);

            uint64_t cipher = des(bytes_to_uint64(block), ctx->des.subkeys, ctx->des.decrypt_mode);
            append_cipher_to_output(cipher, ctx->des.buffer.out, &ctx->des.buffer.out_pos);
        }

        if (ctx->des.buffer.bytes_read < BASE64_BUFFER_SIZE)
        {
            printf("BREAK\n");
            printf("==================\n");
            break;
        }

        remaining = 0;
    }

    printf("TOTAL_CIPHER_SIZE: %lu\n", total_cipher_size);

    if (!ctx->des.decrypt_mode && ((total_cipher_size % 8) == 0))
        add_padding_block(ctx, ctx->des.buffer.out, &ctx->des.buffer.out_pos);

    if (ctx->des.decrypt_mode)
        remove_padding(cmd, ctx, ctx->des.buffer.out, &ctx->des.buffer.out_pos);

    if (ctx->des.buffer.out_pos > 0)
        write_des_output(cmd, ctx);

    if (ctx->des.buffer.bytes_read == -1)
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_base64_ctx);

    clear_des_ctx(ctx);
}
