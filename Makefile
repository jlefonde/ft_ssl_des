NAME = ft_ssl

SOURCES_DIR = srcs
HEADERS_DIR = includes
OBJECTS_DIR = objs

SOURCES = ssl.c \
			utils.c \
			digest.c \
			md5.c \
			sha256.c \
			blake2.c \
			blake2s.c \
			blake2b.c \
			base64.c \
			hmac.c \
			pbkdf2.c \
			des.c \
			des_ecb.c

OBJECTS = $(addprefix $(OBJECTS_DIR)/, $(SOURCES:.c=.o))

CFLAGS = -I$(HEADERS_DIR) -g #-Wall -Wextra -Werror
LDFLAGS = -L./libft -lft -lm -lbsd #-lcrypto

all: ./libft/libft.a $(NAME)

$(NAME): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)

$(OBJECTS_DIR)/%.o: $(SOURCES_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) -rf $(OBJECTS_DIR)

fclean: clean
	$(RM) -f $(NAME)
	@make fclean -C ./libft

re: fclean all

./libft/libft.a:
	make bonus -C ./libft

.PHONY: all clean fclean re
