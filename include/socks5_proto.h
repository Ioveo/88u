#ifndef SOCKS5_PROTO_H
#define SOCKS5_PROTO_H

#include <stddef.h>

size_t socks5_build_hello(unsigned char *buf, size_t cap, int want_auth);
int socks5_build_auth(unsigned char *buf, size_t cap, const char *user, const char *pass);

#endif
