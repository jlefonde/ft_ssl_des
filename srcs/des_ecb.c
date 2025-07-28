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
    if (ctx->des.decrypt_mode)
    {
        printf("SALT: ");
        for (int i = 0; i < 8; i++)
            printf("%02x ", ctx->des.salt[i]);
        printf("\n");

        printf("remainder_size: %ld\n", ctx->des.remainder_size);
        printf("remainder: ");
        for (int i = 0; i < ctx->des.remainder_size; i++)
            printf("%02x ", ctx->des.remainder[i]);
        printf("\n");
    }
    // END DEBUG

    while ((ctx->des.buffer.bytes_read = read_from_input(&ctx->des.in, ctx->des.buffer.in, BASE64_BUFFER_SIZE)) > 0)
    {
        size_t size = ctx->des.buffer.bytes_read;
        if (ctx->des.decrypt_mode && ctx->des.base64_mode)
        {
            // buffer.in will contain the remaining bytes that couldnt be decoded
            // and the decode buffer starting at + remaining_size 
            decode_base64_buffer(cmd, ctx, ctx->des.buffer.in, &ctx->des.buffer.bytes_read, &size);
        }

        printf("bytes_read: %ld\n", ctx->des.buffer.bytes_read);
        printf("size: %ld\n", size);

        ctx->des.buffer.total_bytes_read += ctx->des.buffer.bytes_read;

        // TODO: handle b64 encoding so might instead to store it in buffer_out and update out_pos
        if (!ctx->des.decrypt_mode && ctx->des.prepend_salt)
            prepend_salt_to_output(ctx);

        if ((ctx->des.buffer.out_pos + 8) >= BASE64_BUFFER_SIZE)
            write_des_output(cmd, ctx);

        // Make sure it use the correct size as well as a multiple of 8
        // put the remaining bytes in the buffer in for next read
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
