#include "ssl.h"

void init_des_cbc_mode(t_context *ctx)
{
    ctx->des.prev_block = bytes_to_uint64(ctx->des.iv);
}

void process_des_cbc_block(t_context *ctx, uint8_t *in_block, size_t remaining_bytes, size_t bytes_to_append,
    uint64_t (*des_func)(uint64_t block, uint64_t *subkeys, bool decrypt_mode))
{
    if (!ctx->des.decrypt_mode)
    {
        pkcs7(in_block, remaining_bytes);
        uint64_t xor_result = bytes_to_uint64(in_block) ^ ctx->des.prev_block;
        ctx->des.prev_block = des_func(xor_result, ctx->des.subkeys, ctx->des.decrypt_mode);
        append_to_output(ctx->des.prev_block, ctx->des.buffer.out, &ctx->des.buffer.out_pos, bytes_to_append);
    }
    else
    {
        uint64_t des_output = des_func(bytes_to_uint64(in_block), ctx->des.subkeys, ctx->des.decrypt_mode);
        uint64_t plain = des_output ^ ctx->des.prev_block;
        ctx->des.prev_block = bytes_to_uint64(in_block);
        append_to_output(plain, ctx->des.buffer.out, &ctx->des.buffer.out_pos, bytes_to_append);
    }
}

void finalize_des_cbc_mode(const t_command *cmd, t_context *ctx,
    uint64_t (*des_func)(uint64_t block, uint64_t *subkeys, bool decrypt_mode))
{
    if (!ctx->des.decrypt_mode && ((ctx->des.total_input_size % 8) == 0))
    {
        uint8_t block[8];
        process_des_cbc_block(ctx, block, 0, 8, des_func);
    }

    if (ctx->des.decrypt_mode)
        remove_padding(cmd, ctx, ctx->des.buffer.out, &ctx->des.buffer.out_pos); 
}
