#include "ssl.h"

void process_des_ecb(const t_command *cmd, int argc, char **argv)
{   
    t_context *ctx = parse_des(cmd, argc, argv);

    if (!prepare_des(cmd, ctx, false))
    {
        clear_des_ctx(ctx);
        return;
    }

    // DEBUG
    // if (ctx->des.decrypt_mode)
    // {
    //     printf("SALT: ");
    //     for (int i = 0; i < 8; i++)
    //         printf("%02x ", ctx->des.salt[i]);
    //     printf("\n");

    //     printf("remainder_size: %ld\n", ctx->des.b64_remainder_size);
    //     printf("remainder: ");
    //     for (int i = 0; i < ctx->des.b64_remainder_size; i++)
    //         printf("%02x ", ctx->des.b64_remainder[i]);
    //     printf("\n");
    // }
    // END DEBUG

    // TODO: handle b64 encoding so might instead to store it in buffer_out and update out_pos
    // if (!ctx->des.decrypt_mode && ctx->des.prepend_salt)
    //     prepend_salt_to_output(ctx);

    while (true)
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

        bool is_last_chunk = ctx->des.buffer.bytes_read < (DES_BUFFER_SIZE - b64_offset);
        
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

        size_t complete_groups = input_buffer_size / 8;
        size_t aligned_size = input_buffer_size * 8;
        size_t remainder_size = input_buffer_size - aligned_size;

        if (remainder_size > 0)
        {
            ft_memcpy(ctx->des.des_remainder, input_buffer + aligned_size, remainder_size);
            ctx->des.des_remainder_size = remainder_size;
        }

        for (int i = 0; i < aligned_size; i += 8)
        {
            uint8_t block[8];
            ft_memcpy(block, input_buffer + i, 8);

            if (!ctx->des.decrypt_mode)
                pkcs7(block, aligned_size - i);

            uint64_t cipher = des(bytes_to_uint64(block), ctx->des.subkeys, ctx->des.decrypt_mode);
            append_cipher_to_output(cipher, ctx->des.buffer.out, &ctx->des.buffer.out_pos);
        }

        if (is_last_chunk && !ctx->des.b64_remainder_size && !ctx->des.des_remainder_size)
            break;
    }

    // TODO: should use total cipher size
    // if (!ctx->des.decrypt_mode && ((ctx->des.buffer.total_bytes_read % 8) == 0))
    //     add_padding(ctx, ctx->des.buffer.out, &ctx->des.buffer.out_pos);

    // if (ctx->des.decrypt_mode)
    //     remove_padding(cmd, ctx, ctx->des.buffer.out, &ctx->des.buffer.out_pos);

    // if (ctx->des.buffer.out_pos > 0)
    //     write_des_output(cmd, ctx);

    clear_des_ctx(ctx);
}
