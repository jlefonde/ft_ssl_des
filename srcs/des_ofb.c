#include "ssl.h"

void init_des_ofb_mode(t_context *ctx)
{
    ctx->des.keystream = bytes_to_uint64(ctx->des.iv);
}

void process_des_ofb_block(t_context *ctx, uint8_t *in_block, size_t remaining_bytes, size_t bytes_to_append)
{
    (void)remaining_bytes;
    
    ctx->des.keystream = des(ctx->des.keystream, ctx->des.subkeys, false);
    uint64_t out_block = ctx->des.keystream ^ bytes_to_uint64(in_block);
    append_to_output(out_block, ctx->des.buffer.out, &ctx->des.buffer.out_pos, bytes_to_append);
}
