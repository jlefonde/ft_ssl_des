#include "ssl.h"

static const char g_base64_alphabet[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

void clear_base64_ctx(t_context *ctx)
{
    if (ctx->base64.in != STDIN_FILENO)
        close(ctx->base64.in);
    if (ctx->base64.out != STDOUT_FILENO)
        close(ctx->base64.out);
    free(ctx);
}

static int get_fd(t_context *ctx, const char *file, int default_fd, bool is_output)
{
    int fd = default_fd;
    if (file)
    {
        int flags = is_output ? (O_WRONLY | O_CREAT | O_TRUNC) : O_RDONLY;

        fd = open(file, flags, is_output ? 0644 : 0);
        if (fd == -1)
            fatal_error(ctx, file, strerror(errno), NULL, clear_base64_ctx);
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
                fatal_error(ctx, cmd->name, argv[i], "Unknown option", clear_base64_ctx);
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
            fatal_error(ctx, cmd->name, "Extra option", argv[i], clear_base64_ctx);
    }

    if (in_mode)
        fatal_error(ctx, cmd->name, NULL, "Option -i needs a value", clear_base64_ctx);
    else if (out_mode)
        fatal_error(ctx, cmd->name, NULL, "Option -o needs a value", clear_base64_ctx);

    ctx->base64.in = get_fd(ctx, in_file, ctx->base64.in, false);
    ctx->base64.out = get_fd(ctx, out_file, ctx->base64.out, true);

    return (ctx);
}

static void append_output(t_buffer *buffer, char c)
{
    buffer->out[buffer->out_pos++] = c;
    buffer->total_bytes_written++;
    if (buffer->total_bytes_written % 64 == 0)
        buffer->out[buffer->out_pos++] = '\n';
}

static void write_output(t_context *ctx, t_buffer *buffer)
{
    write(ctx->base64.out, buffer->out, buffer->out_pos);
    ft_memset(buffer->out, 0x00, buffer->out_pos);
    buffer->out_pos = 0;
}

static void encode_base64(const t_command *cmd, t_context *ctx)
{
    t_buffer buffer;

    buffer.bytes_read = 0;
    buffer.total_bytes_written = 0;
    buffer.out_pos = 0;

    while ((buffer.bytes_read = read(ctx->base64.in, buffer.in, BUFFER_SIZE)) > 0)
    {
        for (int i = 0; i < buffer.bytes_read; i += 3)
        {
            if (buffer.out_pos > BUFFER_SIZE - 53)
                write_output(ctx, &buffer);
            int nbytes = buffer.bytes_read - i > 3 ? 3 : buffer.bytes_read - i;
            int pad = 3 - nbytes;

            ssize_t indices[4] = { -1, -1, -1, -1 };

            indices[0] = buffer.in[i] >> 2;
            indices[1] = ((buffer.in[i] & 0b00000011) << 4);
            if (nbytes > 1)
            {
                indices[1] |= (buffer.in[i + 1] >> 4);
                indices[2] = ((buffer.in[i + 1] & 0b00001111) << 2);
                if (nbytes > 2)
                {
                    indices[2] |= ((buffer.in[i + 2] & 0b11000000) >> 6);
                    indices[3] = buffer.in[i + 2] & 0b00111111;
                }
            }

            for (int j = 0; j < 4; j++)
                if (indices[j] >= 0)
                    append_output(&buffer, g_base64_alphabet[indices[j]]);
            for (int j = 0; j < pad; j++)
                append_output(&buffer, '=');
        }
    }

    if (buffer.out_pos)
        write_output(ctx, &buffer);

    if ((buffer.total_bytes_written % 64) != 0)
        write(ctx->base64.out, "\n", 1);

    if (buffer.bytes_read == -1)
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_base64_ctx);
}

static uint8_t get_base64_char_index(char c, size_t *npad)
{
    if (c == '=')
    {
        (*npad)++;
        return (0);
    }
    for (int i = 0; i < 64; i++)
    {
        if (c == g_base64_alphabet[i])
            return (i);
    }
    return (-1);
}

static void decode_base64(const t_command *cmd, t_context *ctx)
{
    t_buffer buffer;
    
    buffer.bytes_read = 0;
    buffer.out_pos = 0;

    uint8_t bytes[4];
    size_t byte_count = 0;
    size_t npad = 0;

    while ((buffer.bytes_read = read(ctx->base64.in, buffer.in, BUFFER_SIZE)) > 0)
    {
        for (int i = 0; i < buffer.bytes_read; i++)
        {
            if (buffer.in[i] == '\n')
                continue;

            bytes[byte_count] = get_base64_char_index(buffer.in[i], &npad);
            if (bytes[byte_count] >= 64
                || (npad > 0 && buffer.in[i] != '=')
                || (byte_count < 2 && buffer.in[i] == '='))
            {
                write_output(ctx, &buffer);
                fatal_error(ctx, cmd->name, "Invalid input", NULL, clear_base64_ctx); 
            }
            byte_count++;

            if (byte_count == 2)
                buffer.out[buffer.out_pos++] = ((bytes[0] & 0b00111111) << 2) | (bytes[1] >> 4);
            else if (byte_count == 3 && npad == 0)
                buffer.out[buffer.out_pos++] = ((bytes[1] & 0b00001111) << 4) | (bytes[2] >> 2);
            else if (byte_count == 4)
            {
                if (buffer.out_pos > BUFFER_SIZE - 3)
                    write_output(ctx, &buffer);
                
                if (npad == 0)
                    buffer.out[buffer.out_pos++] = ((bytes[2] & 0b00000011) << 6) | (bytes[3] & 0b00111111);
                
                byte_count = 0;
                npad = 0;
            }
        }
    }

    if (buffer.out_pos)
        write_output(ctx, &buffer);
    if (byte_count != 0 && (byte_count != 3 && npad != 0))
        fatal_error(ctx, cmd->name, "Invalid input", NULL, clear_base64_ctx); 

    if (buffer.bytes_read == -1)
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_base64_ctx);
}

void process_base64(const t_command *cmd, int argc, char **argv)
{
    t_context *ctx = parse_base64(cmd, argc, argv);

    if (ctx->base64.decode_mode)
        decode_base64(cmd, ctx);
    else
        encode_base64(cmd, ctx);
    clear_base64_ctx(ctx);
}
