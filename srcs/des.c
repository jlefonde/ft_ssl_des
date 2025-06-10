#include "ssl.h"

static const size_t g_ip[64] = {
    58,	50,	42,	34,	26,	18,	10,	2, 60, 52, 44, 36, 28, 20, 12, 4,
    62,	54,	46,	38,	30,	22,	14,	6, 64, 56, 48, 40, 32, 24, 16, 8,
    57,	49,	41,	33,	25,	17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61,	53,	45,	37,	29,	21,	13,	5, 63, 55, 47, 39, 31, 23, 15, 7
};

static const size_t g_fp[64] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25
};

static const size_t g_e[48] = {
    32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,  8,  9, 10, 11, 
    12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
};

static const size_t g_p[32] = {
    16, 7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5,  18, 31, 10,
    2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6,  22, 11,  4, 25
};

static const size_t g_pc1[56] = {
    57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
};

static const size_t g_pc2[48] = {
    14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

static const size_t g_s[8][4][16] = {
    { 
        { 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7 },
        {  0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8 },
        {  4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0 },
        { 15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13 }
    },
    {
        { 15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10 },
        {  3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5 },
        {  0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15 },
        { 13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9 }
    },
    {
        { 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8 },
        { 13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1 },
        { 13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7 },
        {  1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 }
    },
    {
        {  7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15 },
        { 13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9 },
        { 10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4 },
        {  3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14 }
    },
    {
        {  2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9 },
        { 14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6 },
        {  4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14 },
        { 11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3 }
    },
    {
        { 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11 },
        { 10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8, },
        {  9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6, },
        {  4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13 }
    },
    {
        {  4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1 },
        { 13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6 },
        {  1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2 },
        {  6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12 }
    },
    {
        { 13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7 },
        {  1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2 },
        {  7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8 },
        {  2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 }
    }
};

static const size_t g_rot[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

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
    ctx->des.pbkdf2_mode = false;

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
            else if (ft_strcmp(argv[i], "-P") == 0)
                ctx->des.pbkdf2_mode = true;
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
            ctx->des.key = ft_strdup(argv[i]);
            key_mode = false;
        }
        else if (password_mode)
        {
            ctx->des.password = ft_strdup(argv[i]);
            password_mode = false;
        }
        else if (salt_mode)
        {
            ctx->des.salt = ft_strdup(argv[i]);
            salt_mode = false;
        }
        else if (iv_mode)
        {
            ctx->des.iv = ft_strdup(argv[i]);
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

uint64_t apply_block_permutation(uint64_t input, const size_t *p_arr)
{
    uint64_t p = 0;

    for (int i = 0; i < 64; i++)
    {
        if ((input >> (p_arr[i] - 1)) & 1)
            p |= ((uint64_t)1 << (63 - i));
    }

    return (p);
}

uint32_t apply_feistel_permutation(uint32_t input, const size_t *p_arr)
{
    uint32_t p = 0;

    for (int i = 0; i < 32; i++)
    {
        if (input & ((uint32_t)1 << (p_arr[i] - 1)))
            p |= ((uint32_t)1 << (31 - i));
    }

    return (p);
}

void print_bits(uint64_t value)
{
    for (int i = 63; i >= 0; i--)
    {
        printf("%lu", (value >> i) & 1);
        if (i % 8 == 0) printf(" ");
    }
    printf("\n");
}

uint32_t feistel(uint32_t input)
{
    return 0;
}

void des(uint64_t input)
{   
    printf("input:\t%#018lx\n", input);
    uint64_t ip = apply_block_permutation(input, g_ip);
    printf("ip:\t%#018lx\n", ip);

    uint32_t left_half = (ip & 0xFFFFFFFF00000000) >> 32;
    uint32_t right_half = ip & 0xFFFFFFFF;

    printf("left:\t%#010x\n", left_half);
    printf("right:\t%#010x\n", right_half);

    for (int i = 0; i < 16; i++)
    {
        uint32_t next_right_half = feistel(right_half) ^ left_half;

        left_half = right_half;
        right_half = next_right_half;
    }

    printf("left:\t%#010x\n", left_half);
    printf("right:\t%#010x\n", right_half);

    uint64_t combined_halves = ((uint64_t)right_half << 32) | left_half;
    printf("comb:\t%#018lx\n", combined_halves);

    uint64_t fp = apply_block_permutation(combined_halves, g_fp);
    printf("fp:\t%#018lx\n", fp);
}
