#ifndef PARSE_H
#define PARSE_H

#include <stddef.h>

typedef struct {
    int   *ports;
    size_t count;
    size_t cap;
} PortList;

typedef struct {
    unsigned int start;
    unsigned int end;
} IpRange;

typedef struct {
    IpRange *ranges;
    size_t   count;
    size_t   cap;
} IpList;

typedef struct {
    IpList *list;
    size_t  range_idx;
    unsigned int cur_ip;
} IpIter;

unsigned int ip_to_u32(const char *s);
void u32_to_ip(unsigned int ip, char *buf, size_t len);

PortList parse_ports(const char *s);
void portlist_free(PortList *pl);

int parse_token_ipv4(IpList *list, const char *token);
unsigned long long count_token_fast_ipv4(IpList *list);

void iptok_init_iter(IpIter *it, IpList *list);
int iptok_next(IpIter *it, unsigned int *out);

void iplist_free(IpList *list);

#endif
