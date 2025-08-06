#include "ssl.h"

void init_des_cfb_mode(t_context *ctx)
{
    ctx->des.keystream = bytes_to_uint64(ctx->des.iv);
}

void process_des_cfb_block(t_context *ctx, uint8_t *in_block, size_t remaining_bytes, size_t bytes_to_append,
    uint64_t (*des_func)(uint64_t block, uint64_t *subkeys, bool decrypt_mode))
{
    (void)remaining_bytes;

    if (!ctx->des.decrypt_mode)
    {
        uint64_t cipher = des_func(ctx->des.keystream, ctx->des.subkeys, ctx->des.decrypt_mode);
        ctx->des.keystream = cipher ^ bytes_to_uint64(in_block);
        append_to_output(ctx->des.keystream, ctx->des.buffer.out, &ctx->des.buffer.out_pos, bytes_to_append);
    }
    else
    {
        uint64_t cipher = des_func(ctx->des.keystream, ctx->des.subkeys, false);
        ctx->des.keystream = bytes_to_uint64(in_block);
        append_to_output(cipher ^ ctx->des.keystream, ctx->des.buffer.out, &ctx->des.buffer.out_pos, bytes_to_append);
    }
}
