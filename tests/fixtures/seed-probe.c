#include <stdio.h>
#include <stdint.h>
#include <linux/types.h>

static volatile __int128 divisor = ((__int128)1 << 70) + 7;
static volatile __int128 numerator = (((__int128)1 << 70) + 7) * 12345 + 6;

int main(void) {
    __u32 width = sizeof(uint64_t);
    if (width != 8 || numerator / divisor != 12345 || numerator % divisor != 6)
        return 1;
    return puts("seed compiler probe") < 0;
}
