#include "ssl.h"

void process_des_cfb(const t_command *cmd, int argc, char **argv)
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
    uint64_t cipher;
    bool is_last_chunk = false;
    while (!is_last_chunk)
    {
        if ((ctx->des.buffer.out_pos + 8) >= DES_BUFFER_SIZE)
            write_des_output(cmd, ctx);

        handle_remainder(ctx->des.buffer.in, NULL, ctx->des.b64_remainder, &ctx->des.b64_remainder_size,
            &ctx->des.b64_offset);

        ctx->des.buffer.bytes_read = read_from_input(&ctx->des.in, ctx->des.buffer.in + ctx->des.b64_offset,
            DES_BUFFER_SIZE - ctx->des.b64_offset);
        if (ctx->des.buffer.bytes_read == -1)
            fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_des_ctx);

        is_last_chunk = ctx->des.buffer.bytes_read < (DES_BUFFER_SIZE - ctx->des.b64_offset);

        uint8_t des_buffer[DES_BUFFER_SIZE + 7];
        size_t des_buffer_size = 0;
        handle_remainder(des_buffer, &des_buffer_size, ctx->des.des_remainder, &ctx->des.des_remainder_size, 
            &ctx->des.des_offset);

        prepare_des_buffer(cmd, ctx, des_buffer, &des_buffer_size, is_last_chunk);

        size_t aligned_size = align_buffer(ctx, des_buffer, des_buffer_size, is_last_chunk);

        uint64_t previous_cipher;
        uint64_t previous_input_cipher;
        for (int i = 0; i < aligned_size; i += 8)
        {
            size_t bytes_to_write = 8;
            if (is_last_chunk && (i + 8 > des_buffer_size))
                bytes_to_write = des_buffer_size - i;

            if (!ctx->des.decrypt_mode)
            {
                uint64_t block = is_first_block ? bytes_to_uint64(ctx->des.iv) : previous_cipher;

                cipher = des(block, ctx->des.subkeys, ctx->des.decrypt_mode);
                previous_cipher = cipher ^ bytes_to_uint64(des_buffer + i);
                append_cipher_to_output(previous_cipher, ctx->des.buffer.out, &ctx->des.buffer.out_pos, 
                    bytes_to_write);
            }
            else
            {
                uint64_t block = is_first_block ? bytes_to_uint64(ctx->des.iv) : previous_input_cipher;

                cipher = des(block, ctx->des.subkeys, false);
                previous_input_cipher = bytes_to_uint64(des_buffer + i);
                uint64_t plain = cipher ^ previous_input_cipher;
                append_cipher_to_output(plain, ctx->des.buffer.out, &ctx->des.buffer.out_pos, bytes_to_write);
            }

            is_first_block = false;
        }
    }

    if (ctx->des.buffer.out_pos > 0)
        write_des_output(cmd, ctx);

    clear_des_ctx(ctx);
}
