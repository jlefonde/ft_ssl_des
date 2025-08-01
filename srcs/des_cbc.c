#include "ssl.h"

void process_des_cbc(const t_command *cmd, int argc, char **argv)
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

        size_t b64_offset = 0;
        if (ctx->des.b64_remainder_size > 0)
        {
            ft_memcpy(ctx->des.buffer.in, ctx->des.b64_remainder, ctx->des.b64_remainder_size);
            b64_offset = ctx->des.b64_remainder_size;
            ctx->des.b64_remainder_size = 0;
        }

        ctx->des.buffer.bytes_read = read_from_input(&ctx->des.in, ctx->des.buffer.in + b64_offset,
            DES_BUFFER_SIZE - b64_offset);
        if (ctx->des.buffer.bytes_read == -1)
            fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_des_ctx);

        is_last_chunk = ctx->des.buffer.bytes_read < (DES_BUFFER_SIZE - b64_offset);

        uint8_t input_buffer[DES_BUFFER_SIZE + 7];
        size_t input_buffer_size = 0;
        size_t des_offset = 0;
        if (ctx->des.des_remainder_size > 0)
        {
            ft_memcpy(input_buffer, ctx->des.des_remainder, ctx->des.des_remainder_size);
            des_offset = ctx->des.des_remainder_size;
            input_buffer_size = des_offset;
            ctx->des.des_remainder_size = 0;
        }
        
        if (ctx->des.decrypt_mode && ctx->des.base64_mode)
        {
            size_t buffer_size = ctx->des.buffer.bytes_read + b64_offset;

            size_t decoded_size = 0;
            uint8_t *decoded_buffer = decode_base64_buffer(cmd, ctx, ctx->des.buffer.in, buffer_size, &decoded_size, 
                is_last_chunk);
            if (!decoded_buffer)
                fatal_error(ctx, NULL, NULL, NULL, clear_des_ctx);

            ft_memcpy(input_buffer + des_offset, decoded_buffer, decoded_size);
            input_buffer_size += decoded_size;
            free(decoded_buffer);
        }
        else
        {
            ft_memcpy(input_buffer + des_offset, ctx->des.buffer.in, ctx->des.buffer.bytes_read);
            input_buffer_size += ctx->des.buffer.bytes_read;
        }

        ctx->des.total_input_size += input_buffer_size;
        size_t aligned_size = input_buffer_size;
        if (!is_last_chunk)
        {
            size_t complete_groups = input_buffer_size / 8;
            aligned_size = complete_groups * 8;
            size_t remainder_size = input_buffer_size - aligned_size;

            if (remainder_size > 0)
            {
                ft_memcpy(ctx->des.des_remainder, input_buffer + aligned_size, remainder_size);
                ctx->des.des_remainder_size = remainder_size;
            }
        }

        for (int i = 0; i < aligned_size; i += 8)
        {
            uint8_t block[8];
            ft_memcpy(block, input_buffer + i, 8);
    
            if (!ctx->des.decrypt_mode)
            {
                pkcs7(block, aligned_size - i);

                uint64_t new_block = bytes_to_uint64(block);

                new_block ^= is_first_block ? bytes_to_uint64(ctx->des.iv) : cipher;

                cipher = des(new_block, ctx->des.subkeys, ctx->des.decrypt_mode);
                append_cipher_to_output(cipher, ctx->des.buffer.out, &ctx->des.buffer.out_pos);
            }
            else
            {
                uint64_t current_cipher = bytes_to_uint64(block);
                uint64_t decrypted = des(current_cipher, ctx->des.subkeys, ctx->des.decrypt_mode);
                uint64_t new_block = decrypted;

                new_block ^= is_first_block ? bytes_to_uint64(ctx->des.iv) : cipher;

                cipher = current_cipher;
                append_cipher_to_output(new_block, ctx->des.buffer.out, &ctx->des.buffer.out_pos);
            }

            is_first_block = false;
        }
    }

    if (!ctx->des.decrypt_mode && ((ctx->des.total_input_size % 8) == 0))
    {
        uint8_t block[8];

        pkcs7(block, 0);

        for (int j = 0; j < 8; j++)
        {
            if (is_first_block)
                block[j] ^= ctx->des.iv[j];
            else
                block[j] ^= (cipher >> (56 - (j * 8))) & 0xFF;
        }

        cipher = des(bytes_to_uint64(block), ctx->des.subkeys, ctx->des.decrypt_mode);
        append_cipher_to_output(cipher, ctx->des.buffer.out, &ctx->des.buffer.out_pos);
    }

    if (ctx->des.decrypt_mode)
        remove_padding(cmd, ctx, ctx->des.buffer.out, &ctx->des.buffer.out_pos);

    if (ctx->des.buffer.out_pos > 0)
        write_des_output(cmd, ctx);

    clear_des_ctx(ctx);
}
