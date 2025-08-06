#include "ssl.h"

void process_des_ecb_block(t_context *ctx, uint8_t *in_block, size_t remaining_bytes, size_t bytes_to_append)
{
    if (!ctx->des.decrypt_mode)
        pkcs7(in_block, remaining_bytes);

    uint64_t out_block = des(bytes_to_uint64(in_block), ctx->des.subkeys, ctx->des.decrypt_mode);
    append_to_output(out_block, ctx->des.buffer.out, &ctx->des.buffer.out_pos, bytes_to_append);
}

void finalize_des_ecb_mode(const t_command *cmd, t_context *ctx)
{
    if (!ctx->des.decrypt_mode && ((ctx->des.total_input_size % 8) == 0))
    {
        uint8_t block[8];
        process_des_ecb_block(ctx, block, 0, 8);
    }

    if (ctx->des.decrypt_mode)
        remove_padding(cmd, ctx, ctx->des.buffer.out, &ctx->des.buffer.out_pos); 
}
