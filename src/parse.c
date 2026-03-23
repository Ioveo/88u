#include "../include/parse.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int cmp_int(const void *a, const void *b) {
    return (*(const int *)a) - (*(const int *)b);
}

unsigned int ip_to_u32(const char *s) {
    struct in_addr addr;
    if (inet_pton(AF_INET, s, &addr) != 1) return 0;
    return ntohl(addr.s_addr);
}

void u32_to_ip(unsigned int ip, char *buf, size_t len) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    inet_ntop(AF_INET, &addr, buf, len);
}

static void iplist_add(IpList *list, unsigned int start, unsigned int end) {
    if (list->count >= list->cap) {
        list->cap = list->cap ? list->cap * 2 : 256;
        list->ranges = realloc(list->ranges, list->cap * sizeof(IpRange));
    }
    list->ranges[list->count].start = start;
    list->ranges[list->count].end = end;
    list->count++;
}

int parse_token_ipv4(IpList *list, const char *token) {
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s", token);

    char *slash = strchr(tmp, '/');
    if (slash) {
        *slash = 0;
        unsigned int base = ip_to_u32(tmp);
        if (base == 0 && strcmp(tmp, "0.0.0.0") != 0) return -1;
        int prefix = (int)strtol(slash + 1, NULL, 10);
        if (prefix < 0 || prefix > 32) return -1;
        unsigned int mask = prefix == 0 ? 0 : (~0U << (32 - prefix));
        unsigned int start = base & mask;
        unsigned int end = start | ~mask;
        iplist_add(list, start, end);
        return 0;
    }

    char *dash = strchr(tmp, '-');
    if (dash) {
        if (strchr(dash + 1, '.')) {
            *dash = 0;
            unsigned int s = ip_to_u32(tmp);
            unsigned int e = ip_to_u32(dash + 1);
            if (s == 0 || e == 0 || s > e) return -1;
            iplist_add(list, s, e);
            return 0;
        }
        *dash = 0;
        unsigned int s = ip_to_u32(tmp);
        if (s == 0) return -1;
        int end_octet = (int)strtol(dash + 1, NULL, 10);
        if (end_octet < 0 || end_octet > 255) return -1;
        unsigned int e = (s & 0xFFFFFF00) | (unsigned int)end_octet;
        if (s > e) return -1;
        iplist_add(list, s, e);
        return 0;
    }

    unsigned int ip = ip_to_u32(tmp);
    if (ip == 0 && strcmp(tmp, "0.0.0.0") != 0) return -1;
    iplist_add(list, ip, ip);
    return 0;
}

unsigned long long count_token_fast_ipv4(IpList *list) {
    unsigned long long total = 0;
    for (size_t i = 0; i < list->count; i++) {
        total += (unsigned long long)(list->ranges[i].end - list->ranges[i].start + 1);
    }
    return total;
}

void iptok_init_iter(IpIter *it, IpList *list) {
    it->list = list;
    it->range_idx = 0;
    it->cur_ip = (list->count > 0) ? list->ranges[0].start : 0;
}

int iptok_next(IpIter *it, unsigned int *out) {
    while (it->range_idx < it->list->count) {
        IpRange *r = &it->list->ranges[it->range_idx];
        if (it->cur_ip <= r->end) {
            *out = it->cur_ip++;
            return 1;
        }
        it->range_idx++;
        if (it->range_idx < it->list->count)
            it->cur_ip = it->list->ranges[it->range_idx].start;
    }
    return 0;
}

PortList parse_ports(const char *s) {
    PortList pl = {0};
    char *dup = strdup(s);
    char *tok = strtok(dup, ", \t");
    while (tok) {
        char *dash = strchr(tok, '-');
        if (dash) {
            *dash = 0;
            int a = (int)strtol(tok, NULL, 10);
            int b = (int)strtol(dash + 1, NULL, 10);
            for (int p = a; p <= b && p <= 65535; p++) {
                if (pl.count >= pl.cap) {
                    pl.cap = pl.cap ? pl.cap * 2 : 64;
                    pl.ports = realloc(pl.ports, pl.cap * sizeof(int));
                }
                pl.ports[pl.count++] = p;
            }
        } else {
            int p = (int)strtol(tok, NULL, 10);
            if (p > 0 && p <= 65535) {
                if (pl.count >= pl.cap) {
                    pl.cap = pl.cap ? pl.cap * 2 : 64;
                    pl.ports = realloc(pl.ports, pl.cap * sizeof(int));
                }
                pl.ports[pl.count++] = p;
            }
        }
        tok = strtok(NULL, ", \t");
    }
    free(dup);
    if (pl.count > 1) {
        qsort(pl.ports, pl.count, sizeof(int), cmp_int);
        size_t j = 1;
        for (size_t i = 1; i < pl.count; i++) {
            if (pl.ports[i] != pl.ports[j - 1])
                pl.ports[j++] = pl.ports[i];
        }
        pl.count = j;
    }
    return pl;
}

void portlist_free(PortList *pl) {
    if (!pl) return;
    free(pl->ports);
    pl->ports = NULL;
    pl->count = 0;
    pl->cap = 0;
}

void iplist_free(IpList *list) {
    if (!list) return;
    free(list->ranges);
    list->ranges = NULL;
    list->count = 0;
    list->cap = 0;
}
