#include "ssl.h"

void process_des_ecb(const t_command *cmd, int argc, char **argv)
{   
    t_context *ctx = parse_des(cmd, argc, argv);

    if (!prepare_des(cmd, ctx, false))
    {
        clear_des_ctx(ctx);
        return;
    }

    // TODO: add buffer to des ctx and free buffers on exit
    ssize_t bytes_read = 0;
    ssize_t total_bytes_read = 0;
    uint8_t *in_buffer = malloc(BASE64_BUFFER_SIZE);
    uint8_t out_buffer[BASE64_BUFFER_SIZE];
    size_t out_pos = 0;

    while ((bytes_read = read_from_input(&ctx->des.in, in_buffer, BASE64_BUFFER_SIZE)) > 0)
    {
        if (ctx->des.decrypt_mode && ctx->des.base64_mode)
        {
            size_t decoded_size = 0;

            uint8_t *decoded_buffer = decode_base64_flag(cmd, in_buffer, bytes_read, &decoded_size);
            if (!decoded_buffer)
                fatal_error(ctx, NULL, NULL, NULL, clear_des_ctx);

            free(in_buffer);
            in_buffer = decoded_buffer;
            bytes_read = decoded_size;
        }

        total_bytes_read += bytes_read;

        if (!ctx->des.decrypt_mode && ctx->des.prepend_salt)
            prepend_salt_to_output(ctx);

        if ((out_pos + 8) >= BASE64_BUFFER_SIZE)
            write_output(ctx->des.out_fd, out_buffer, &out_pos);

        for (int i = 0; i < bytes_read; i += 8)
        {
            uint8_t block[8];
            ft_memcpy(block, in_buffer + i, 8);

            if (!ctx->des.decrypt_mode)
                pkcs7(block, bytes_read - i);

            uint64_t cipher = des(bytes_to_uint64(block), ctx->des.subkeys, ctx->des.decrypt_mode);
            append_cipher_to_output(cipher, out_buffer, &out_pos);
        }

        if (bytes_read < BASE64_BUFFER_SIZE)
            break;
    }

    if (!ctx->des.decrypt_mode && ((total_bytes_read % 8) == 0))
        add_padding_block(ctx, out_buffer, &out_pos);

    if (ctx->des.decrypt_mode)
        remove_padding(cmd, ctx, out_buffer, &out_pos);

    if (out_pos > 0)
        write_output(ctx->des.out_fd, out_buffer, &out_pos);

    if (bytes_read == -1)
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_base64_ctx);

    clear_des_ctx(ctx);
}
