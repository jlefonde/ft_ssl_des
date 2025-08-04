#include "ssl.h"

void process_des3_cbc(const t_command *cmd, int argc, char **argv)
{   
    t_context *ctx = parse_des(cmd, argc, argv, DES3_KEY_LEN);

    if (!prepare_des(cmd, ctx, true, DES3_KEY_LEN))
    {
        clear_des_ctx(ctx);
        return;
    }

    if (!ctx->des.decrypt_mode && ctx->des.prepend_salt)
        prepend_salt_to_output(ctx, ctx->des.buffer.out, &ctx->des.buffer.out_pos);

    uint64_t previous_cipher = 0;
    bool is_first_block = true;
    bool is_last_chunk = false;
    while (!is_last_chunk)
    {
        uint8_t des_buffer[DES_BUFFER_SIZE + 7];
        size_t des_buffer_size = 0;
        size_t aligned_size = process_des_input_chunk(cmd, ctx, des_buffer, &des_buffer_size, &is_last_chunk);

        for (size_t i = 0; i < aligned_size; i += 8)
        {
            uint8_t block[8];
            ft_memcpy(block, des_buffer + i, 8);

            if (!ctx->des.decrypt_mode)
            {
                pkcs7(block, aligned_size - i);

                uint64_t plain = bytes_to_uint64(block);
                uint64_t xor_result = plain ^ (is_first_block ? bytes_to_uint64(ctx->des.iv) : previous_cipher);
                
                uint64_t cipher;
                cipher = des(xor_result, ctx->des.subkeys, false);
                cipher = des(cipher, ctx->des.subkeys + 16, true);
                cipher = des(cipher, ctx->des.subkeys + 32, false);
                previous_cipher = cipher;
                append_cipher_to_output(cipher, ctx->des.buffer.out, &ctx->des.buffer.out_pos, 8);
            }
            else
            {
                uint64_t cipher = bytes_to_uint64(block);
                
                uint64_t des_output;
                des_output = des(cipher, ctx->des.subkeys + 32, true);
                des_output = des(des_output, ctx->des.subkeys + 16, false);
                des_output = des(des_output, ctx->des.subkeys, true);

                uint64_t plain = des_output ^ (is_first_block ? bytes_to_uint64(ctx->des.iv) : previous_cipher);
                previous_cipher = cipher;
                append_cipher_to_output(plain, ctx->des.buffer.out, &ctx->des.buffer.out_pos, 8);
            }

            is_first_block = false;
        }
    }

    if (!ctx->des.decrypt_mode && ((ctx->des.total_input_size % 8) == 0))
    {
        uint8_t block[8];
        pkcs7(block, 0);

        uint64_t new_block = bytes_to_uint64(block);
        new_block ^= is_first_block ? bytes_to_uint64(ctx->des.iv) : previous_cipher;

        uint64_t cipher = des(new_block, ctx->des.subkeys, ctx->des.decrypt_mode);
        append_cipher_to_output(cipher, ctx->des.buffer.out, &ctx->des.buffer.out_pos, 8);
    }

    if (ctx->des.decrypt_mode)
        remove_padding(cmd, ctx, ctx->des.buffer.out, &ctx->des.buffer.out_pos);

    if (ctx->des.buffer.out_pos > 0)
        write_des_output(cmd, ctx);

    clear_des_ctx(ctx);
}
