#include "ssl.h"

void process_des_ofb(const t_command *cmd, int argc, char **argv)
{   
    t_context *ctx = parse_des(cmd, argc, argv);

    if (!prepare_des(cmd, ctx, true))
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

        uint64_t previous_keystream;
        for (int i = 0; i < aligned_size; i += 8)
        {
            uint64_t block = is_first_block ? bytes_to_uint64(ctx->des.iv) : previous_keystream;

            size_t bytes_to_write = 8;
            if (is_last_chunk && (i + 8 > des_buffer_size))
                bytes_to_write = des_buffer_size - i;

            uint64_t keystream = des(block, ctx->des.subkeys, false);
            previous_keystream = keystream;
            uint64_t output_block = keystream ^ bytes_to_uint64(des_buffer + i);
            append_cipher_to_output(output_block, ctx->des.buffer.out, &ctx->des.buffer.out_pos, bytes_to_write);

            is_first_block = false;
        }
    }

    if (ctx->des.buffer.out_pos > 0)
        write_des_output(cmd, ctx);

    clear_des_ctx(ctx);
}
