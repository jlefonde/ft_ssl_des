#include "ssl.h"

static const char g_alphabet[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

static int get_fd(t_context *ctx, const char *file, int default_fd, bool is_output)
{
    int fd = default_fd;
    if (file)
    {
        int flags = is_output ? (O_WRONLY | O_CREAT | O_TRUNC) : O_RDONLY;
    
        fd = open(file, flags, is_output ? 0644 : 0);
        if (fd == -1)
            fatal_error(ctx, file, strerror(errno), NULL);
    }
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

    ctx->base64.in = STDIN_FILENO;
    ctx->base64.out = STDOUT_FILENO;
    ctx->base64.decode_mode = false;

    char *in_file = NULL;
    char *out_file = NULL;
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
            in_file = argv[i];
            in_mode = false;
        }
        else if (out_mode)
        {
            out_file = argv[i];
            out_mode = false;
        }
        else
            fatal_error(ctx, cmd->name, "Extra option", argv[i]);
    }

    if (in_mode)
        fatal_error(ctx, cmd->name, NULL, "Option -i needs a value");
    else if (out_mode)
        fatal_error(ctx, cmd->name, NULL, "Option -o needs a value");

    ctx->base64.in = get_fd(ctx, in_file, ctx->base64.in, false);
    ctx->base64.out = get_fd(ctx, out_file, ctx->base64.out, true);

    return (ctx);
}

void process_base64(const t_command *cmd, int argc, char **argv)
{
    t_context *ctx = parse_base64(cmd, argc, argv);

    printf("in: %d\n", ctx->base64.in);
    printf("out: %d\n", ctx->base64.out);
    printf("decode: %d\n", ctx->base64.decode_mode);

    uint8_t buffer[BUFFER_SIZE];
    ssize_t bytes_read = 0;
    while ((bytes_read = read(ctx->base64.in, buffer, BUFFER_SIZE)) > 0)
    {
        for (int i = 0; i < bytes_read; i += 3)
        {
            int8_t indices[4];
            ft_memset(indices, -1, 4);

            indices[0] = buffer[i] >> 2;
            indices[1] = ((buffer[i] & 0b00000011) << 4);
            if ((i + 1) < bytes_read)
            {
                indices[1] |= (buffer[i + 1] >> 4);
                indices[2] = ((buffer[i + 1] & 0b00001111) << 2);
                if ((i + 2) < bytes_read)
                {
                    indices[2] |= ((buffer[i + 2] & 0b11000000) >> 6);
                    indices[3] = buffer[i + 2] & 0b00111111;
                }
            }
            for (int j = 0; j < 4; j++)
            {
                if (indices[j] >= 0)
                    ft_fprintf(ctx->base64.out, "%c", g_alphabet[indices[j]]);
            }
            if (indices[2] == -1)
                ft_fprintf(ctx->base64.out, "=");
            if (indices[1] == -1)
                ft_fprintf(ctx->base64.out, "=");
        }
    }
    ft_fprintf(ctx->base64.out, "\n");

    if (bytes_read == -1)
    {
        close(ctx->base64.in);
        close(ctx->base64.out);
        fatal_error(ctx, cmd->name, strerror(errno), NULL);
    }

    close(ctx->base64.in);
    close(ctx->base64.out);
    free(ctx);
}
