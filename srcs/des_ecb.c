#include "ssl.h"

void process_des_ecb(const t_command *cmd, int argc, char **argv)
{   
    t_context *ctx = parse_des(cmd, argc, argv);

    if (!prepare_des(cmd, ctx, false))
    {
        clear_des_ctx(ctx);
        return;
    }

    if (!ctx->des.decrypt_mode && ctx->des.prepend_salt)
        prepend_salt_to_output(ctx, ctx->des.buffer.out, &ctx->des.buffer.out_pos);

    bool is_last_chunk = false;
    while (!is_last_chunk)
    {
        uint8_t des_buffer[DES_BUFFER_SIZE + 7];
        size_t des_buffer_size = 0;
        size_t aligned_size = process_des_input_chunk(cmd, ctx, des_buffer, &des_buffer_size, &is_last_chunk);

        for (int i = 0; i < aligned_size; i += 8)
        {
            uint8_t block[8];
            ft_memcpy(block, des_buffer + i, 8);

            if (!ctx->des.decrypt_mode)
                pkcs7(block, aligned_size - i);

            uint64_t cipher = des(bytes_to_uint64(block), ctx->des.subkeys, ctx->des.decrypt_mode);
            append_cipher_to_output(cipher, ctx->des.buffer.out, &ctx->des.buffer.out_pos, 8);
        }
    }

    if (!ctx->des.decrypt_mode && ((ctx->des.total_input_size % 8) == 0))
        add_full_padding_block(ctx, ctx->des.buffer.out, &ctx->des.buffer.out_pos);

    if (ctx->des.decrypt_mode)
        remove_padding(cmd, ctx, ctx->des.buffer.out, &ctx->des.buffer.out_pos);

    if (ctx->des.buffer.out_pos > 0)
        write_des_output(cmd, ctx);

    clear_des_ctx(ctx);
}
