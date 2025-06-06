#include "ssl.h"

void clear_des_ctx(t_context *ctx)
{
    if (ctx->des.in != STDIN_FILENO)
        close(ctx->des.in);
    if (ctx->des.out != STDOUT_FILENO)
        close(ctx->des.out);
    free(ctx);
}

t_context *parse_des(const t_command *cmd, int argc, char **argv)
{   
    t_context *ctx = (t_context *)malloc(sizeof(t_context));
    if (!ctx)
    {
        print_error(cmd->name, strerror(errno), NULL);
        exit(EXIT_FAILURE);
    }

    ctx->des.in = STDIN_FILENO;
    ctx->des.out = STDOUT_FILENO;
    ctx->des.key = NULL;
    ctx->des.password = NULL;
    ctx->des.salt = NULL;
    ctx->des.iv = NULL;
    ctx->des.decrypt_mode = false;
    ctx->des.base64_mode = false;

    char *in_file = NULL;
    char *out_file = NULL;
    bool in_mode = false;
    bool out_mode = false;
    bool key_mode = false;
    bool password_mode = false;
    bool salt_mode = false;
    bool iv_mode = false;
    for (int i = 2; i < argc; ++i)
    {
        bool input_mode = (in_mode || out_mode);

        if (!input_mode && argv[i][0] == '-')
        {
            if (ft_strcmp(argv[i], "-d") == 0)
                ctx->des.decrypt_mode = true;
            else if (ft_strcmp(argv[i], "-e") == 0)
                ctx->des.decrypt_mode = false;
            else if (ft_strcmp(argv[i], "-a") == 0)
                ctx->des.base64_mode = true;
            else if (ft_strcmp(argv[i], "-i") == 0)
                in_mode = true;
            else if (ft_strcmp(argv[i], "-o") == 0)
                out_mode = true;
            else if (ft_strcmp(argv[i], "-k") == 0)
                key_mode = true;
            else if (ft_strcmp(argv[i], "-p") == 0)
                password_mode = true;
            else if (ft_strcmp(argv[i], "-s") == 0)
                salt_mode = true;
            else if (ft_strcmp(argv[i], "-v") == 0)
                iv_mode = true;
            else
                fatal_error(ctx, cmd->name, argv[i], "Unknown option", clear_des_ctx);
        }
        else if (in_mode)
        {
            in_file = argv[i];
            in_mode = false;
        }
        else if (out_mode)
        {
            out_file = argv[i];
            out_mode = false;
        }
        else if (key_mode)
        {
            ctx->des.key = argv[i];
            key_mode = false;
        }
        else if (password_mode)
        {
            ctx->des.password = argv[i];
            password_mode = false;
        }
        else if (salt_mode)
        {
            ctx->des.salt = argv[i];
            salt_mode = false;
        }
        else if (iv_mode)
        {
            ctx->des.iv = argv[i];
            iv_mode = false;
        }
        else
            fatal_error(ctx, cmd->name, "Extra option", argv[i], clear_des_ctx);
    }

    if (in_mode)
        fatal_error(ctx, cmd->name, NULL, "Option -i needs a value", clear_des_ctx);
    else if (out_mode)
        fatal_error(ctx, cmd->name, NULL, "Option -o needs a value", clear_des_ctx);
    else if (key_mode)
        fatal_error(ctx, cmd->name, NULL, "Option -k needs a value", clear_des_ctx);
    else if (password_mode)
        fatal_error(ctx, cmd->name, NULL, "Option -p needs a value", clear_des_ctx);
    else if (salt_mode)
        fatal_error(ctx, cmd->name, NULL, "Option -s needs a value", clear_des_ctx);
    else if (iv_mode)
        fatal_error(ctx, cmd->name, NULL, "Option -iv needs a value", clear_des_ctx);

    ctx->des.in = get_fd(ctx, in_file, ctx->des.in, false);
    ctx->des.out = get_fd(ctx, out_file, ctx->des.out, true);

    return (ctx);
}
