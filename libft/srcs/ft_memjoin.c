#include "../includes/libft.h"

void *ft_memjoin(void const *s1, size_t s1_len, void const *s2, size_t s2_len)
{
    uint8_t *dest = malloc(s1_len + s2_len);
    if (!dest)
        return (NULL);
    ft_memcpy(dest, s1, s1_len);
    ft_memcpy(dest + s1_len, s2, s2_len);
    return (dest);
}
