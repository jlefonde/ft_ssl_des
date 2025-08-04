#include "ssl.h"

void process_des_cfb(const t_command *cmd, int argc, char **argv)
{   
    t_context *ctx = parse_des(cmd, argc, argv, DES_KEY_LEN);

    if (!prepare_des(cmd, ctx, true, DES_KEY_LEN))
    {
        clear_des_ctx(ctx);
        return;
    }

    if (!ctx->des.decrypt_mode && ctx->des.prepend_salt)
        prepend_salt_to_output(ctx, ctx->des.buffer.out, &ctx->des.buffer.out_pos);

    bool is_first_block = true;
    bool is_last_chunk = false;
    while (!is_last_chunk)
    {
        uint8_t des_buffer[DES_BUFFER_SIZE + 7];
        size_t des_buffer_size = 0;
        size_t aligned_size = process_des_input_chunk(cmd, ctx, des_buffer, &des_buffer_size, &is_last_chunk);

        uint64_t previous_cipher;
        for (int i = 0; i < aligned_size; i += 8)
        {
            size_t bytes_to_write = 8;
            if (is_last_chunk && (i + 8 > des_buffer_size))
                bytes_to_write = des_buffer_size - i;

            if (!ctx->des.decrypt_mode)
            {
                uint64_t feedback_block = is_first_block ? bytes_to_uint64(ctx->des.iv) : previous_cipher;

                uint64_t keystream = des(feedback_block, ctx->des.subkeys, false);
                uint64_t cipher = keystream ^ bytes_to_uint64(des_buffer + i);
                previous_cipher = cipher;
                append_cipher_to_output(cipher, ctx->des.buffer.out, &ctx->des.buffer.out_pos, 
                    bytes_to_write);
            }
            else
            {
                uint64_t feedback_block = is_first_block ? bytes_to_uint64(ctx->des.iv) : previous_cipher;

                uint64_t keystream = des(feedback_block, ctx->des.subkeys, false);
                uint64_t current_cipher = bytes_to_uint64(des_buffer + i);
                previous_cipher = current_cipher;
                uint64_t plain = keystream ^ current_cipher;
                append_cipher_to_output(plain, ctx->des.buffer.out, &ctx->des.buffer.out_pos, bytes_to_write);
            }

            is_first_block = false;
        }
    }

    if (ctx->des.buffer.out_pos > 0)
        write_des_output(cmd, ctx);

    clear_des_ctx(ctx);
}
