#include "ssl.h"

void process_des_cbc(const t_command *cmd, int argc, char **argv)
{   
    t_context *ctx = parse_des(cmd, argc, argv);

    if (!ctx->des.password && !ctx->des.key)
        ctx->des.password = ask_password(cmd, ctx);

    if (!ctx->des.salt)
        ctx->des.salt = generate_random_bytes(cmd, ctx, 8);

    if (!ctx->des.iv)
        ctx->des.iv = generate_random_bytes(cmd, ctx, 8);

    if (!ctx->des.key)
        ctx->des.key = pbkdf2(hmac_sha256, 32, ctx->des.password, ft_strlen(ctx->des.password),
            ctx->des.salt, DES_SALT_LEN, DES_PBKDF_ITR, DES_KEY_LEN);

    if (ctx->des.print_mode)
        des_print_mode(ctx, true);
    
    clear_des_ctx(ctx);
}
