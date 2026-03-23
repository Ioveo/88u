#include "../include/socks5_proto.h"
#include <string.h>

size_t socks5_build_hello(unsigned char *buf, size_t cap, int want_auth) {
    size_t nmethods = want_auth ? 2 : 1;
    size_t need = 2 + nmethods;
    if (cap < need) return 0;
    buf[0] = 0x05;
    buf[1] = (unsigned char)nmethods;
    buf[2] = 0x00;
    if (want_auth) buf[3] = 0x02;
    return need;
}

int socks5_build_auth(unsigned char *buf, size_t cap, const char *user, const char *pass) {
    size_t ulen = user ? strlen(user) : 0;
    size_t plen = pass ? strlen(pass) : 0;
    size_t need = 3 + ulen + plen;
    if (ulen > 255 || plen > 255) return -1;
    if (cap < need) return -1;
    buf[0] = 0x01;
    buf[1] = (unsigned char)ulen;
    if (ulen > 0) memcpy(buf + 2, user, ulen);
    buf[2 + ulen] = (unsigned char)plen;
    if (plen > 0) memcpy(buf + 3 + ulen, pass, plen);
    return (int)need;
}
