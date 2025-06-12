#include "ssl.h"

// openssl enc -des-ecb -pbkdf2 -provider default -provider legacy -P
// openssl enc -des-ecb -pbkdf2 -provider default -provider legacy -pass pass:test -S "ABC" -P
void process_des_ecb(const t_command *cmd, int argc, char **argv)
{   
    t_context *ctx = parse_des(cmd, argc, argv);

    if (ctx->des.iv)
        write(STDERR_FILENO, "warning: iv not used by this cipher\n", 36);

    if (!ctx->des.password && !ctx->des.key)
        ctx->des.password = ask_password(cmd, ctx);

    if (!ctx->des.salt)
        ctx->des.salt = generate_random_bytes(cmd, ctx, 8);

    if (!ctx->des.key)
        ctx->des.key = pbkdf2(hmac_sha256, 32, ctx->des.password, ft_strlen(ctx->des.password), ctx->des.salt, DES_SALT_LEN, 1000, 8);

    if (ctx->des.print_mode)
        des_print_mode(ctx, false);
}
