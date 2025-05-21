#include "ssl.h"

static int get_default_fd(t_context *ctx, const char *file, int default_fd, bool is_output)
{
    int fd = default_fd;
    if (file)
        fd = get_fd(ctx, file, is_output);
    return (fd);
}

static t_context *parse_base64(const t_command *cmd, int argc, char **argv)
{
    t_context *ctx = (t_context *)malloc(sizeof(t_context));
    if (!ctx)
    {
        print_error(cmd->name, strerror(errno), NULL);
        exit(EXIT_FAILURE);
    }

    ctx->base64.in = NULL;
    ctx->base64.out = NULL;
    ctx->base64.decode_mode = false;

    bool in_mode = false;
    bool out_mode = false;
    for (int i = 2; i < argc; ++i)
    {
        bool file_mode = (in_mode || out_mode);

        if (!file_mode && argv[i][0] == '-')
        {
            if (ft_strcmp(argv[i], "-d") == 0)
                ctx->base64.decode_mode = true;
            else if (ft_strcmp(argv[i], "-e") == 0)
                ctx->base64.decode_mode = false;
            else if (ft_strcmp(argv[i], "-i") == 0)
                in_mode = true;
            else if (ft_strcmp(argv[i], "-o") == 0)
                out_mode = true;
            else
                fatal_error(ctx, cmd->name, argv[i], "Unknown option");
        }
        else if (in_mode)
        {
            ctx->base64.in = argv[i];
            in_mode = false;
        }
        else if (out_mode)
        {
            ctx->base64.out = argv[i];
            out_mode = false;
        }
        else
            fatal_error(ctx, cmd->name, "Extra option", argv[i]);
    }

    if (in_mode)
        fatal_error(ctx, cmd->name, NULL, "Option -i needs a value");
    else if (out_mode)
        fatal_error(ctx, cmd->name, NULL, "Option -o needs a value");

    return (ctx);
}

void process_base64(const t_command *cmd, int argc, char **argv)
{
    t_context *ctx = parse_base64(cmd, argc, argv);

    printf("in: %s\n", ctx->base64.in);
    printf("out: %s\n", ctx->base64.out);
    printf("decode: %d\n", ctx->base64.decode_mode);

    int in_fd = get_default_fd(ctx, ctx->base64.in, STDIN_FILENO, false);
    int out_fd = get_default_fd(ctx, ctx->base64.out, STDOUT_FILENO, false);

    char buffer[BUFFER_SIZE];
    ssize_t bytes_read = 0;
    while ((bytes_read = read(in_fd, buffer, BUFFER_SIZE)) > 0)
    {
        buffer[bytes_read] = 0;
        
    }

    if (bytes_read == -1)
    {
        close(in_fd);
        close(out_fd);
        fatal_error(ctx, cmd->name, strerror(errno), NULL);
    }

    close(in_fd);
    close(out_fd);
    free(ctx);
}
