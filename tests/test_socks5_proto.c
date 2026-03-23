#include "../include/socks5_proto.h"

int main(void) {
    unsigned char buf[8];
    unsigned char abuf[512];

    size_t n = socks5_build_hello(buf, sizeof(buf), 1);
    if (n != 4) return 1;
    if (buf[0] != 0x05 || buf[1] != 0x02 || buf[2] != 0x00 || buf[3] != 0x02) return 1;

    n = socks5_build_hello(buf, sizeof(buf), 0);
    if (n != 3) return 1;
    if (buf[0] != 0x05 || buf[1] != 0x01 || buf[2] != 0x00) return 1;

    int alen = socks5_build_auth(abuf, sizeof(abuf), "u", "p");
    if (alen != 5) return 1;
    if (abuf[0] != 0x01 || abuf[1] != 0x01 || abuf[2] != 'u' || abuf[3] != 0x01 || abuf[4] != 'p') return 1;

    return 0;
}
