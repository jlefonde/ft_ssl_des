#include "ssl.h"

static const char g_base64_alphabet[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

void clear_base64_ctx(t_context *ctx)
{
    if (ctx->base64.in.fd != STDIN_FILENO)
        close(ctx->base64.in.fd);
    if (ctx->base64.out_fd != STDOUT_FILENO)
        close(ctx->base64.out_fd);
    free(ctx);
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

static t_context *parse_base64(const t_command *cmd, int argc, char **argv)
{
    t_context *ctx = (t_context *)malloc(sizeof(t_context));
    if (!ctx)
    {
        print_error(cmd->name, strerror(errno), NULL);
        exit(EXIT_FAILURE);
    }

    ctx->base64.in.fd = STDIN_FILENO;
    ctx->base64.out_fd = STDOUT_FILENO;
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

    ctx->base64.in.fd = get_fd(in_file, ctx->base64.in.fd, false);
    if (ctx->base64.in.fd == -1)
            fatal_error(ctx, in_file, strerror(errno), NULL, clear_base64_ctx);

    ctx->base64.out_fd = get_fd(out_file, ctx->base64.out_fd, true);
    if (ctx->base64.out_fd == -1)
            fatal_error(ctx, out_file, strerror(errno), NULL, clear_base64_ctx);

    ctx->base64.in.type = (ctx->base64.in.fd == STDIN_FILENO) ? INPUT_STDIN : INPUT_FILE;
    ctx->base64.in.data_pos = -1;

    return (ctx);
}

static void append_output(uint8_t *out_buffer, size_t *out_pos, size_t *total_bytes_written, char c)
{
    out_buffer[(*out_pos)++] = c;
    (*total_bytes_written)++;
    if (*total_bytes_written % 64 == 0)
        out_buffer[(*out_pos)++] = '\n';
}

static void encode_base64(const t_command *cmd, t_context *ctx)
{
    uint8_t in_buffer[BASE64_BUFFER_SIZE];
    uint8_t out_buffer[BASE64_BUFFER_SIZE];
    ssize_t bytes_read = 0;
    size_t  total_bytes_written = 0;
    size_t  out_pos = 0;

    while ((bytes_read = read_from_input(&ctx->base64.in, in_buffer, BASE64_BUFFER_SIZE)) > 0)
    {
        for (int i = 0; i < bytes_read; i += 3)
        {
            if (out_pos > BASE64_BUFFER_SIZE - 53)
                write_output(ctx->base64.out_fd, out_buffer, &out_pos);

            int nbytes = bytes_read - i > 3 ? 3 : bytes_read - i;
            int npad = 3 - nbytes;

            ssize_t indices[4] = { -1, -1, -1, -1 };

            indices[0] = in_buffer[i] >> 2;
            indices[1] = ((in_buffer[i] & 0b00000011) << 4);
            if (nbytes > 1)
            {
                indices[1] |= (in_buffer[i + 1] >> 4);
                indices[2] = ((in_buffer[i + 1] & 0b00001111) << 2);
                if (nbytes > 2)
                {
                    indices[2] |= ((in_buffer[i + 2] & 0b11000000) >> 6);
                    indices[3] = in_buffer[i + 2] & 0b00111111;
                }
            }

            for (int j = 0; j < 4; j++)
                if (indices[j] >= 0)
                    append_output(out_buffer, &out_pos, &total_bytes_written, g_base64_alphabet[indices[j]]);

            for (int j = 0; j < npad; j++)
                append_output(out_buffer, &out_pos, &total_bytes_written, '=');
        }
    }

    if (out_pos)
        write_output(ctx->base64.out_fd, out_buffer, &out_pos);

    if ((total_bytes_written % 64) != 0)
        write(ctx->base64.out_fd, "\n", 1);

    if (bytes_read == -1)
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_base64_ctx);
}

static void decode_base64(const t_command *cmd, t_context *ctx)
{
    uint8_t in_buffer[BASE64_BUFFER_SIZE];
    uint8_t out_buffer[BASE64_BUFFER_SIZE];
    ssize_t bytes_read = 0;
    size_t  out_pos = 0;

    uint8_t bytes[4];
    size_t byte_count = 0;
    size_t npad = 0;

    while ((bytes_read = read_from_input(&ctx->base64.in, in_buffer, BASE64_BUFFER_SIZE)) > 0)
    {
        for (int i = 0; i < bytes_read; i++)
        {
            if (ft_isspace(in_buffer[i]))
                continue;

            bytes[byte_count] = get_base64_char_index(in_buffer[i], &npad);
            if (bytes[byte_count] >= 64
                || (npad > 0 && in_buffer[i] != '=')
                || (byte_count < 2 && in_buffer[i] == '='))
            {
                write_output(ctx->base64.out_fd, out_buffer, &out_pos);
                fatal_error(ctx, cmd->name, "Invalid input", NULL, clear_base64_ctx); 
            }
            byte_count++;

            if (byte_count == 2)
                out_buffer[out_pos++] = ((bytes[0] & 0b00111111) << 2) | (bytes[1] >> 4);
            else if (byte_count == 3 && npad == 0)
                out_buffer[out_pos++] = ((bytes[1] & 0b00001111) << 4) | (bytes[2] >> 2);
            else if (byte_count == 4)
            {
                if (npad == 0)
                    out_buffer[out_pos++] = ((bytes[2] & 0b00000011) << 6) | (bytes[3] & 0b00111111);

                if (out_pos > BASE64_BUFFER_SIZE - 3)
                    write_output(ctx->base64.out_fd, out_buffer, &out_pos);

                byte_count = 0;
                npad = 0;
            }
        }
    }

    if (out_pos)
        write_output(ctx->base64.out_fd, out_buffer, &out_pos);

    if (byte_count != 0 || (byte_count != 3 && npad != 0))
        fatal_error(ctx, cmd->name, "Invalid input", NULL, clear_base64_ctx); 

    if (bytes_read == -1)
        fatal_error(ctx, cmd->name, strerror(errno), NULL, clear_base64_ctx);
}

uint8_t *encode_base64_flag(const t_command *cmd, uint8_t *input, size_t n, size_t *encoded_size)
{
    uint8_t *out_buffer = malloc(BASE64_BUFFER_SIZE * 2);
    if (!out_buffer)
    {
        print_error(cmd->name, "base64", strerror(errno));
        return (NULL);
    }

    size_t  total_bytes_written = 0;
    size_t  out_pos = 0;

    for (size_t i = 0; i < n; i += 3)
    {
        int nbytes = n - i > 3 ? 3 : n - i;
        int npad = 3 - nbytes;

        ssize_t indices[4] = { -1, -1, -1, -1 };

        indices[0] = input[i] >> 2;
        indices[1] = ((input[i] & 0b00000011) << 4);
        if (nbytes > 1)
        {
            indices[1] |= (input[i + 1] >> 4);
            indices[2] = ((input[i + 1] & 0b00001111) << 2);
            if (nbytes > 2)
            {
                indices[2] |= ((input[i + 2] & 0b11000000) >> 6);
                indices[3] = input[i + 2] & 0b00111111;
            }
        }

        for (int j = 0; j < 4; j++)
            if (indices[j] >= 0)
                append_output(out_buffer, &out_pos, &total_bytes_written, g_base64_alphabet[indices[j]]);

        for (int j = 0; j < npad; j++)
            append_output(out_buffer, &out_pos, &total_bytes_written, '=');
    }

    if ((total_bytes_written % 64) != 0)
        out_buffer[out_pos++] = '\n';

    *encoded_size = out_pos;
    return (out_buffer);
}

uint8_t *decode_base64_flag(const t_command *cmd, uint8_t *input, size_t n, size_t *decoded_size)
{
    uint8_t *out_buffer = malloc(n);
    if (!out_buffer)
    {
        print_error(cmd->name, "base64", strerror(errno));
        return (NULL);
    }

    uint8_t bytes[4];
    size_t out_pos = 0;
    size_t byte_count = 0;
    size_t npad = 0;

    for (size_t i = 0; i < n; i++)
    {
        bytes[byte_count] = get_base64_char_index(input[i], &npad);
        if (bytes[byte_count] >= 64
            || (npad > 0 && input[i] != '=')
            || (byte_count < 2 && input[i] == '='))
        {
            print_error(cmd->name, "base64", "Invalid input");
            free(out_buffer);
            return (NULL);
        }

        byte_count++;

        if (byte_count == 2)
            out_buffer[out_pos++] = ((bytes[0] & 0b00111111) << 2) | (bytes[1] >> 4);
        else if (byte_count == 3 && npad == 0)
            out_buffer[out_pos++] = ((bytes[1] & 0b00001111) << 4) | (bytes[2] >> 2);
        else if (byte_count == 4)
        {
            if (npad == 0)
                out_buffer[out_pos++] = ((bytes[2] & 0b00000011) << 6) | (bytes[3] & 0b00111111);

            byte_count = 0;
            npad = 0;
        }
    }

    if (byte_count != 0 || (byte_count != 3 && npad != 0))
    {
        print_error(cmd->name, "base64", "Invalid input");
        free(out_buffer);
        return (NULL);
    }
    
    *decoded_size = out_pos;
    return (out_buffer);
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
