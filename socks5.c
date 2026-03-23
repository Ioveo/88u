/*
 * socks5.c - Socks代理扫描工具 v5.0
 * kqueue 事件驱动架构 | 单线程管理 1000+ 并发连接
 * Target: FreeBSD x86-64, compile with: cc -o socks5 socks5.c
 *
 * 用法:
 *   交互式: ./socks5
 *   命令行: ./socks5 -i check.txt -p 1080 -t 1000 -T 5 -o socks.txt -c credentials.txt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/event.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>

/* ======================== 常量与默认值 ======================== */
#define DEFAULT_PORT       "1080"
#define DEFAULT_CRED_FILE  "credentials.txt"
#define DEFAULT_OUTPUT     "socks.txt"
#define DEFAULT_CHECK      "check.txt"
#define DEFAULT_CONNS      "1000"
#define DEFAULT_TIMEOUT    "5"
#define MAX_EVENTS         512
#define MAX_POOL           8192

/* ======================== 连接状态机 ======================== */

typedef enum {
    CS_CONNECTING,          /* 非阻塞 connect 进行中 */
    CS_HS_RECV,             /* 等待 SOCKS5 握手响应 */
    CS_VERIFY_RECV,         /* 等待 CONNECT 响应 */
    CS_VERIFY_HTTP_RECV,    /* 等待 HTTP 响应 */
    CS_AUTH_CONNECTING,     /* 认证: 非阻塞 connect */
    CS_AUTH_HS_RECV,        /* 认证: 等待握手响应 */
    CS_AUTH_CRED_RECV,      /* 认证: 等待凭证验证响应 */
} ConnPhase;

typedef struct {
    int           fd;
    unsigned int  ip;       /* 主机字节序 */
    int           port;
    ConnPhase     phase;
    int           cred_idx; /* 当前凭证索引 */
    double        deadline; /* 超时截止时间 */
    int           pool_idx; /* 在活跃池中的索引 */
} ConnState;

/* ======================== 数据结构 ======================== */

typedef struct { char *user; char *pass; } Cred;
typedef struct { Cred *items; size_t count; size_t cap; } CredList;
typedef struct { int *ports; size_t count; size_t cap; } PortList;
typedef struct { unsigned int start; unsigned int end; } IpRange;
typedef struct { IpRange *ranges; size_t count; size_t cap; } IpList;
typedef struct { IpList *list; size_t range_idx; unsigned int cur_ip; } IpIter;

/* ======================== 全局状态 ======================== */

static volatile int g_stop = 0;
static unsigned long long g_total_tasks = 0;
static unsigned long long g_done_tasks  = 0;
static unsigned long long g_found       = 0;
static unsigned long long g_auth_total  = 0;
static unsigned long long g_auth_done   = 0;
static FILE *g_outfp = NULL;
static CredList g_creds = {0};
static double g_start_time = 0;
static double g_timeout = 5.0;
static int g_max_concurrent = 1000;

/* 活跃连接池 */
static ConnState *g_pool[MAX_POOL];
static int g_pool_count = 0;

/* ======================== 工具函数 ======================== */

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void on_sigint(int sig) { (void)sig; g_stop = 1; }

static int cmp_int(const void *a, const void *b) {
    return (*(const int *)a) - (*(const int *)b);
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r') s++;
    if (*s == 0) return s;
    char *e = s + strlen(s) - 1;
    while (e > s && (*e == ' ' || *e == '\t' || *e == '\n' || *e == '\r')) *e-- = 0;
    return s;
}

static int is_file(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0);
}

static char *get_input(const char *prompt, const char *def) {
    static char buf[4096];
    printf("%s [默认: %s]: ", prompt, def);
    fflush(stdout);
    if (fgets(buf, sizeof(buf), stdin) == NULL) return strdup(def);
    char *p = trim(buf);
    return strdup(*p ? p : def);
}

static void u32_to_ip(unsigned int ip, char *buf, size_t len) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    inet_ntop(AF_INET, &addr, buf, len);
}

static unsigned int ip_to_u32(const char *s) {
    struct in_addr addr;
    if (inet_pton(AF_INET, s, &addr) != 1) return 0;
    return ntohl(addr.s_addr);
}

/* ======================== 凭证管理 ======================== */

static void add_cred(CredList *cl, const char *user, const char *pass) {
    if (cl->count >= cl->cap) {
        cl->cap = cl->cap ? cl->cap * 2 : 16;
        void *tmp = realloc(cl->items, cl->cap * sizeof(Cred));
        if (!tmp) return;
        cl->items = tmp;
    }
    cl->items[cl->count].user = strdup(user);
    cl->items[cl->count].pass = strdup(pass);
    cl->count++;
}

static void free_creds(CredList *cl) {
    for (size_t i = 0; i < cl->count; i++) { free(cl->items[i].user); free(cl->items[i].pass); }
    free(cl->items); cl->items = NULL; cl->count = cl->cap = 0;
}

static int load_creds(CredList *cl, const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) { fprintf(stderr, "[!] 加载凭证文件出错: %s\n", path); return -1; }
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char *p = trim(line);
        if (*p == 0 || *p == '#') continue;
        char *sep = strchr(p, ':');
        if (sep) { *sep = 0; add_cred(cl, trim(p), trim(sep + 1)); }
        else { char *sp = strpbrk(p, " \t"); if (sp) { *sp = 0; add_cred(cl, trim(p), trim(sp + 1)); } }
    }
    fclose(fp);
    return 0;
}

/* ======================== IP 解析 ======================== */

static void iplist_add(IpList *l, unsigned int s, unsigned int e) {
    if (l->count >= l->cap) { l->cap = l->cap ? l->cap*2 : 256; l->ranges = realloc(l->ranges, l->cap * sizeof(IpRange)); }
    l->ranges[l->count].start = s; l->ranges[l->count].end = e; l->count++;
}

static int parse_token_ipv4(IpList *list, const char *token) {
    char tmp[256]; snprintf(tmp, sizeof(tmp), "%s", token);
    char *slash = strchr(tmp, '/');
    if (slash) {
        *slash = 0; unsigned int base = ip_to_u32(tmp);
        if (base == 0 && strcmp(tmp, "0.0.0.0") != 0) return -1;
        int prefix = (int)strtol(slash+1, NULL, 10);
        if (prefix < 0 || prefix > 32) return -1;
        unsigned int mask = prefix == 0 ? 0 : (~0U << (32 - prefix));
        iplist_add(list, base & mask, (base & mask) | ~mask); return 0;
    }
    char *dash = strchr(tmp, '-');
    if (dash) {
        if (strchr(dash+1, '.')) {
            *dash = 0; unsigned int s = ip_to_u32(tmp), e = ip_to_u32(dash+1);
            if (s == 0 || e == 0 || s > e) return -1;
            iplist_add(list, s, e); return 0;
        }
        *dash = 0; unsigned int s = ip_to_u32(tmp); if (s == 0) return -1;
        int eo = (int)strtol(dash+1, NULL, 10);
        if (eo < 0 || eo > 255) return -1;
        unsigned int e = (s & 0xFFFFFF00) | (unsigned int)eo;
        if (s > e) return -1; iplist_add(list, s, e); return 0;
    }
    unsigned int ip = ip_to_u32(tmp);
    if (ip == 0 && strcmp(tmp, "0.0.0.0") != 0) return -1;
    iplist_add(list, ip, ip); return 0;
}

static unsigned long long iplist_count(IpList *l) {
    unsigned long long t = 0;
    for (size_t i = 0; i < l->count; i++) t += (unsigned long long)(l->ranges[i].end - l->ranges[i].start + 1);
    return t;
}

static void iptok_init(IpIter *it, IpList *l) {
    it->list = l; it->range_idx = 0;
    it->cur_ip = (l->count > 0) ? l->ranges[0].start : 0;
}

static int iptok_next(IpIter *it, unsigned int *out) {
    while (it->range_idx < it->list->count) {
        IpRange *r = &it->list->ranges[it->range_idx];
        if (it->cur_ip <= r->end) { *out = it->cur_ip++; return 1; }
        it->range_idx++;
        if (it->range_idx < it->list->count) it->cur_ip = it->list->ranges[it->range_idx].start;
    }
    return 0;
}

static PortList parse_ports(const char *s) {
    PortList pl = {0}; char *dup = strdup(s), *tok = strtok(dup, ", \t");
    while (tok) {
        char *d = strchr(tok, '-');
        if (d) {
            *d = 0; int a = (int)strtol(tok, NULL, 10), b = (int)strtol(d+1, NULL, 10);
            for (int p = a; p <= b && p <= 65535; p++) {
                if (pl.count >= pl.cap) { pl.cap = pl.cap?pl.cap*2:64; pl.ports = realloc(pl.ports, pl.cap*sizeof(int)); }
                pl.ports[pl.count++] = p;
            }
        } else {
            int p = (int)strtol(tok, NULL, 10);
            if (p > 0 && p <= 65535) {
                if (pl.count >= pl.cap) { pl.cap = pl.cap?pl.cap*2:64; pl.ports = realloc(pl.ports, pl.cap*sizeof(int)); }
                pl.ports[pl.count++] = p;
            }
        }
        tok = strtok(NULL, ", \t");
    }
    free(dup);
    if (pl.count > 1) {
        qsort(pl.ports, pl.count, sizeof(int), cmp_int);
        size_t j = 1;
        for (size_t i = 1; i < pl.count; i++) if (pl.ports[i] != pl.ports[j-1]) pl.ports[j++] = pl.ports[i];
        pl.count = j;
    }
    return pl;
}

/* ======================== 报告与进度 ======================== */

static void report_hit(unsigned int ip, int port, const char *info) {
    char ipbuf[64]; u32_to_ip(ip, ipbuf, sizeof(ipbuf));
    g_found++;
    printf("[+] %s:%d -> %s\n", ipbuf, port, info); fflush(stdout);
    if (g_outfp) { fprintf(g_outfp, "%s:%d -> %s\n", ipbuf, port, info); fflush(g_outfp); }
}

static void print_progress(void) {
    double elapsed = now_sec() - g_start_time;
    double rate = (g_done_tasks > 0 && elapsed > 0) ? g_done_tasks / elapsed : 0;
    double eta = (rate > 0 && g_total_tasks > g_done_tasks) ? (g_total_tasks - g_done_tasks) / rate : 0;
    char eta_buf[64];
    if (eta >= 3600) snprintf(eta_buf, sizeof(eta_buf), "%.1f时", eta/3600);
    else if (eta >= 60) snprintf(eta_buf, sizeof(eta_buf), "%.1f分", eta/60);
    else snprintf(eta_buf, sizeof(eta_buf), "%.1f秒", eta);
    printf("\r%*s\r[*] 探测:%llu/%llu(%.1f%%)|活跃:%d|认证:%llu/%llu|发现:%llu|%.0f/s|剩余:%s",
           90, "", g_done_tasks, g_total_tasks,
           g_total_tasks > 0 ? (double)g_done_tasks/g_total_tasks*100 : 0,
           g_pool_count, g_auth_done, g_auth_total, g_found, rate, eta_buf);
    fflush(stdout);
}

/* ======================== kqueue 连接管理 ======================== */

static void pool_add(ConnState *cs) {
    cs->pool_idx = g_pool_count;
    g_pool[g_pool_count++] = cs;
}

static void pool_remove(ConnState *cs) {
    int idx = cs->pool_idx;
    if (idx < g_pool_count - 1) {
        g_pool[idx] = g_pool[g_pool_count - 1];
        g_pool[idx]->pool_idx = idx;
    }
    g_pool_count--;
}

/* 关闭连接并释放资源 */
static void conn_close(ConnState *cs) {
    if (cs->fd >= 0) close(cs->fd);  /* kqueue 自动移除已关闭 fd 的事件 */
    pool_remove(cs);
    free(cs);
}

/* 注册 kqueue 事件 */
static int kq_register(int kq, int fd, short filter, void *udata) {
    struct kevent kev;
    EV_SET(&kev, fd, filter, EV_ADD | EV_ONESHOT, 0, 0, udata);
    return kevent(kq, &kev, 1, NULL, 0, NULL);
}

/* 创建非阻塞 socket 并发起连接 */
static int make_nonblock_connect(unsigned int ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    /* 非阻塞 */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    /* TCP_NODELAY 减少小包延迟 */
    int on = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(ip);

    int ret = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (ret == 0 || errno == EINPROGRESS) return fd;

    close(fd);
    return -1;
}

/* ======================== 状态机: 启动探测连接 ======================== */

static int start_probe(int kq, unsigned int ip, int port) {
    int fd = make_nonblock_connect(ip, port);
    if (fd < 0) { g_done_tasks++; return -1; }

    ConnState *cs = calloc(1, sizeof(ConnState));
    if (!cs) { close(fd); g_done_tasks++; return -1; }

    cs->fd = fd;
    cs->ip = ip;
    cs->port = port;
    cs->phase = CS_CONNECTING;
    cs->cred_idx = -1;
    cs->deadline = now_sec() + g_timeout;

    pool_add(cs);

    if (kq_register(kq, fd, EVFILT_WRITE, cs) < 0) {
        conn_close(cs);
        g_done_tasks++;
        return -1;
    }

    return 0;
}

/* 启动认证连接 (重新连接同一 IP:Port) */
static int start_auth_conn(int kq, ConnState *cs) {
    int fd = make_nonblock_connect(cs->ip, cs->port);
    if (fd < 0) return -1;

    cs->fd = fd;
    cs->phase = CS_AUTH_CONNECTING;
    cs->deadline = now_sec() + g_timeout;

    if (kq_register(kq, fd, EVFILT_WRITE, cs) < 0) {
        close(fd); cs->fd = -1;
        return -1;
    }
    return 0;
}

/* ======================== 状态机: 事件处理 ======================== */

static void handle_event(int kq, ConnState *cs, struct kevent *ev) {
    /* 错误或 EOF */
    if (ev->flags & EV_ERROR) {
        if (cs->phase <= CS_HS_RECV) g_done_tasks++;
        else if (cs->phase >= CS_AUTH_CONNECTING) g_auth_done++;
        conn_close(cs);
        return;
    }

    switch (cs->phase) {

    /* ─── 探测: 连接完成 ─── */
    case CS_CONNECTING: {
        /* 检查连接是否成功 */
        int err = 0; socklen_t elen = sizeof(err);
        getsockopt(cs->fd, SOL_SOCKET, SO_ERROR, &err, &elen);
        if (err || (ev->flags & EV_EOF)) {
            g_done_tasks++;
            conn_close(cs);
            return;
        }

        /* 发送 SOCKS5 握手: 同时提供 NO AUTH + USER/PASS */
        unsigned char req[4] = {0x05, 0x02, 0x00, 0x02};
        if (send(cs->fd, req, 4, 0) != 4) {
            g_done_tasks++;
            conn_close(cs);
            return;
        }

        cs->phase = CS_HS_RECV;
        cs->deadline = now_sec() + g_timeout;
        kq_register(kq, cs->fd, EVFILT_READ, cs);
        break;
    }

    /* ─── 探测: 收到握手响应 ─── */
    case CS_HS_RECV: {
        unsigned char resp[2] = {0};
        int n = recv(cs->fd, resp, 2, 0);

        if (n != 2 || resp[0] != 0x05) {
            g_done_tasks++;
            conn_close(cs);
            return;
        }

        if (resp[1] == 0x00) {
            /* 无需认证 → 验证代理连通性: 发送 CONNECT 到 1.1.1.1:80 */
            unsigned char creq[] = {
                0x05, 0x01, 0x00, 0x01,
                0x01, 0x01, 0x01, 0x01,   /* 1.1.1.1 */
                0x00, 0x50                /* port 80 */
            };
            if (send(cs->fd, creq, sizeof(creq), 0) != (ssize_t)sizeof(creq)) {
                g_done_tasks++;
                conn_close(cs);
                return;
            }
            cs->phase = CS_VERIFY_RECV;
            cs->deadline = now_sec() + g_timeout;
            kq_register(kq, cs->fd, EVFILT_READ, cs);

        } else if (resp[1] == 0x02) {
            /* 需要认证 */
            g_done_tasks++; /* 探测阶段完成 */
            close(cs->fd); cs->fd = -1;

            if (g_creds.count > 0) {
                g_auth_total += g_creds.count;
                cs->cred_idx = 0;
                if (start_auth_conn(kq, cs) < 0) {
                    /* 全部计入失败 */
                    g_auth_done += g_creds.count;
                    report_hit(cs->ip, cs->port, "Socks5 (需要认证但连接失败)");
                    conn_close(cs);
                }
            } else {
                report_hit(cs->ip, cs->port, "Socks5 (需要认证但无凭证)");
                conn_close(cs);
            }

        } else if (resp[1] == 0xFF) {
            g_done_tasks++;
            conn_close(cs);
        } else {
            char info[128];
            snprintf(info, sizeof(info), "Socks5 (未知认证方式: 0x%02x)", resp[1]);
            report_hit(cs->ip, cs->port, info);
            g_done_tasks++;
            conn_close(cs);
        }
        break;
    }

    /* ─── 验证: 收到 CONNECT 响应 ─── */
    case CS_VERIFY_RECV: {
        unsigned char resp[262] = {0};
        int n = recv(cs->fd, resp, sizeof(resp), 0);

        if (n < 4 || resp[0] != 0x05 || resp[1] != 0x00) {
            /* CONNECT 失败 → 蜜罐或无效代理, 不报告 */
            g_done_tasks++;
            conn_close(cs);
            return;
        }

        /* CONNECT 成功, 发送 HTTP HEAD 验证 */
        const char *hreq = "HEAD / HTTP/1.0\r\nHost: 1.1.1.1\r\n\r\n";
        if (send(cs->fd, hreq, strlen(hreq), 0) != (ssize_t)strlen(hreq)) {
            g_done_tasks++;
            conn_close(cs);
            return;
        }

        cs->phase = CS_VERIFY_HTTP_RECV;
        cs->deadline = now_sec() + g_timeout;
        kq_register(kq, cs->fd, EVFILT_READ, cs);
        break;
    }

    /* ─── 验证: 收到 HTTP 响应 ─── */
    case CS_VERIFY_HTTP_RECV: {
        unsigned char resp[512] = {0};
        int n = recv(cs->fd, resp, sizeof(resp) - 1, 0);

        if (n > 0 && strstr((char *)resp, "HTTP/")) {
            report_hit(cs->ip, cs->port, "Socks5 (已验证)");
        }
        /* 验证失败的不报告 */
        g_done_tasks++;
        conn_close(cs);
        break;
    }

    /* ─── 认证: 连接完成 ─── */
    case CS_AUTH_CONNECTING: {
        int err = 0; socklen_t elen = sizeof(err);
        getsockopt(cs->fd, SOL_SOCKET, SO_ERROR, &err, &elen);
        if (err || (ev->flags & EV_EOF)) {
            g_auth_done++;
            /* 连接失败, 尝试下一个凭证 */
            close(cs->fd); cs->fd = -1;
            cs->cred_idx++;
            if (cs->cred_idx < (int)g_creds.count) {
                if (start_auth_conn(kq, cs) < 0) {
                    g_auth_done += (g_creds.count - cs->cred_idx);
                    report_hit(cs->ip, cs->port, "Socks5 (需要认证但连接失败)");
                    conn_close(cs);
                }
            } else {
                report_hit(cs->ip, cs->port, "Socks5 (需要认证但测试凭证无效)");
                conn_close(cs);
            }
            return;
        }

        /* 发送认证握手 */
        unsigned char req[4] = {0x05, 0x02, 0x00, 0x02};
        if (send(cs->fd, req, 4, 0) != 4) {
            g_auth_done++;
            close(cs->fd); cs->fd = -1;
            cs->cred_idx++;
            if (cs->cred_idx < (int)g_creds.count) {
                if (start_auth_conn(kq, cs) < 0) { g_auth_done += (g_creds.count - cs->cred_idx); conn_close(cs); }
            } else { report_hit(cs->ip, cs->port, "Socks5 (需要认证但测试凭证无效)"); conn_close(cs); }
            return;
        }

        cs->phase = CS_AUTH_HS_RECV;
        cs->deadline = now_sec() + g_timeout;
        kq_register(kq, cs->fd, EVFILT_READ, cs);
        break;
    }

    /* ─── 认证: 收到握手响应 ─── */
    case CS_AUTH_HS_RECV: {
        unsigned char resp[2] = {0};
        int n = recv(cs->fd, resp, 2, 0);

        if (n != 2 || resp[0] != 0x05 || resp[1] != 0x02) {
            g_auth_done++;
            close(cs->fd); cs->fd = -1;
            cs->cred_idx++;
            if (cs->cred_idx < (int)g_creds.count) {
                if (start_auth_conn(kq, cs) < 0) { g_auth_done += (g_creds.count - cs->cred_idx); conn_close(cs); }
            } else { report_hit(cs->ip, cs->port, "Socks5 (需要认证但测试凭证无效)"); conn_close(cs); }
            return;
        }

        /* 发送凭证 */
        Cred *c = &g_creds.items[cs->cred_idx];
        int ulen = (int)strlen(c->user), plen = (int)strlen(c->pass);
        unsigned char authbuf[515]; int alen = 0;
        authbuf[alen++] = 0x01;
        authbuf[alen++] = (unsigned char)ulen;
        memcpy(authbuf + alen, c->user, ulen); alen += ulen;
        authbuf[alen++] = (unsigned char)plen;
        memcpy(authbuf + alen, c->pass, plen); alen += plen;

        if (send(cs->fd, authbuf, alen, 0) != alen) {
            g_auth_done++;
            close(cs->fd); cs->fd = -1;
            cs->cred_idx++;
            if (cs->cred_idx < (int)g_creds.count) {
                if (start_auth_conn(kq, cs) < 0) { g_auth_done += (g_creds.count - cs->cred_idx); conn_close(cs); }
            } else { report_hit(cs->ip, cs->port, "Socks5 (需要认证但测试凭证无效)"); conn_close(cs); }
            return;
        }

        cs->phase = CS_AUTH_CRED_RECV;
        cs->deadline = now_sec() + g_timeout;
        kq_register(kq, cs->fd, EVFILT_READ, cs);
        break;
    }

    /* ─── 认证: 收到凭证验证响应 ─── */
    case CS_AUTH_CRED_RECV: {
        unsigned char resp[2] = {0};
        int n = recv(cs->fd, resp, 2, 0);

        if (n == 2 && resp[1] == 0x00) {
            /* 认证成功 */
            Cred *c = &g_creds.items[cs->cred_idx];
            char info[256];
            snprintf(info, sizeof(info), "Socks5 (认证成功: %s:%s)", c->user, c->pass);
            report_hit(cs->ip, cs->port, info);
            g_auth_done += (g_creds.count - cs->cred_idx); /* 补齐剩余 */
            conn_close(cs);
            return;
        }

        /* 凭证失败, 尝试下一个 */
        g_auth_done++;
        close(cs->fd); cs->fd = -1;
        cs->cred_idx++;

        if (cs->cred_idx < (int)g_creds.count) {
            if (start_auth_conn(kq, cs) < 0) {
                g_auth_done += (g_creds.count - cs->cred_idx);
                report_hit(cs->ip, cs->port, "Socks5 (需要认证但连接失败)");
                conn_close(cs);
            }
        } else {
            report_hit(cs->ip, cs->port, "Socks5 (需要认证但测试凭证无效)");
            conn_close(cs);
        }
        break;
    }
    } /* switch */
}

/* ======================== 超时扫描 ======================== */

static void sweep_timeouts(int kq, double now) {
    (void)kq;
    for (int i = g_pool_count - 1; i >= 0; i--) {
        ConnState *cs = g_pool[i];
        if (now >= cs->deadline) {
            if (cs->phase <= CS_VERIFY_HTTP_RECV && cs->cred_idx < 0)
                g_done_tasks++;
            else if (cs->phase >= CS_AUTH_CONNECTING)
                g_auth_done += (g_creds.count - cs->cred_idx);
            conn_close(cs);
        }
    }
}

/* ======================== 主事件循环 ======================== */

static void event_loop(int kq, IpIter *it, PortList *ports) {
    struct kevent events[MAX_EVENTS];
    struct timespec ts = {0, 100000000}; /* 100ms kevent 超时 */

    size_t port_idx = 0;
    unsigned int cur_ip = 0;
    int has_more = iptok_next(it, &cur_ip);
    double last_sweep = now_sec();
    double last_progress = now_sec();

    while (!g_stop) {
        /* 填充连接到最大并发数 */
        while (g_pool_count < g_max_concurrent && has_more && !g_stop) {
            start_probe(kq, cur_ip, ports->ports[port_idx]);
            port_idx++;
            if (port_idx >= ports->count) {
                port_idx = 0;
                has_more = iptok_next(it, &cur_ip);
            }
        }

        /* 所有任务完成 */
        if (g_pool_count == 0 && !has_more) break;

        /* 等待事件 */
        int n = kevent(kq, NULL, 0, events, MAX_EVENTS, &ts);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* 处理事件 */
        for (int i = 0; i < n && !g_stop; i++) {
            ConnState *cs = (ConnState *)events[i].udata;
            if (cs) handle_event(kq, cs, &events[i]);
        }

        /* 定期超时扫描 */
        double now = now_sec();
        if (now - last_sweep >= 0.5) {
            sweep_timeouts(kq, now);
            last_sweep = now;
        }

        /* 定期进度显示 */
        if (now - last_progress >= 2.0) {
            print_progress();
            last_progress = now;
        }
    }

    /* 清理剩余连接 */
    while (g_pool_count > 0) conn_close(g_pool[0]);
}

/* ======================== 主函数 ======================== */

static void print_banner(void) {
    puts("\n============================================================");
    puts("  S5 Proxy Scanner v5.0 | kqueue 事件驱动 | 1000+ 并发");
    puts("============================================================\n");
}

static void print_usage(const char *prog) {
    printf("用法: %s [选项]\n", prog);
    puts("  -i <IP/文件>      IP地址范围或文件 (默认: check.txt)");
    puts("  -p <端口>         端口范围 (默认: 1080)");
    puts("  -c <凭证文件>     凭证文件 (默认: credentials.txt)");
    puts("  -t <并发数>       最大并发连接数 (默认: 1000)");
    puts("  -T <超时>         连接超时/秒 (默认: 5)");
    puts("  -o <输出文件>     结果输出 (默认: socks.txt)");
    puts("  -h                显示帮助");
}

int main(int argc, char *argv[]) {
    signal(SIGINT, on_sigint);
    signal(SIGPIPE, SIG_IGN);

    char *ip_input = NULL, *port_input = NULL, *cred_input = NULL;
    char *conns_input = NULL, *timeout_input = NULL, *output_input = NULL;
    int interactive = 1;

    int opt;
    while ((opt = getopt(argc, argv, "i:p:c:t:T:o:h")) != -1) {
        interactive = 0;
        switch (opt) {
            case 'i': ip_input = strdup(optarg); break;
            case 'p': port_input = strdup(optarg); break;
            case 'c': cred_input = strdup(optarg); break;
            case 't': conns_input = strdup(optarg); break;
            case 'T': timeout_input = strdup(optarg); break;
            case 'o': output_input = strdup(optarg); break;
            case 'h': print_usage(argv[0]); return 0;
            default: print_usage(argv[0]); return 1;
        }
    }

    print_banner();

    if (interactive) {
        puts("提示: IP支持 单个IP, CIDR, 范围 或文件路径\n");
        ip_input      = get_input("IP地址范围(或文件)", DEFAULT_CHECK);
        port_input    = get_input("端口范围", DEFAULT_PORT);
        cred_input    = get_input("凭证文件", DEFAULT_CRED_FILE);
        conns_input   = get_input("最大并发连接数", DEFAULT_CONNS);
        timeout_input = get_input("连接超时(秒)", DEFAULT_TIMEOUT);
        output_input  = get_input("输出文件", DEFAULT_OUTPUT);
    } else {
        if (!ip_input)      ip_input = strdup(DEFAULT_CHECK);
        if (!port_input)    port_input = strdup(DEFAULT_PORT);
        if (!cred_input)    cred_input = strdup(DEFAULT_CRED_FILE);
        if (!conns_input)   conns_input = strdup(DEFAULT_CONNS);
        if (!timeout_input) timeout_input = strdup(DEFAULT_TIMEOUT);
        if (!output_input)  output_input = strdup(DEFAULT_OUTPUT);
    }

    g_max_concurrent = (int)strtol(conns_input, NULL, 10);
    g_timeout = strtod(timeout_input, NULL);
    if (g_max_concurrent <= 0) g_max_concurrent = 1000;
    if (g_max_concurrent > MAX_POOL) g_max_concurrent = MAX_POOL;
    if (g_timeout <= 0) g_timeout = 5.0;

    /* 检查 fd 限制 */
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        int max_safe = (int)(rl.rlim_cur * 0.8) - 10;
        if (max_safe < 10) max_safe = 10;
        if (g_max_concurrent > max_safe) {
            printf("[!] fd 限制 %llu, 自动调整并发: %d -> %d\n",
                   (unsigned long long)rl.rlim_cur, g_max_concurrent, max_safe);
            g_max_concurrent = max_safe;
        }
    }

    /* 加载凭证 */
    if (is_file(cred_input)) load_creds(&g_creds, cred_input);
    else fprintf(stderr, "[!] 凭证文件 %s 不存在\n", cred_input);
    if (g_creds.count == 0) {
        add_cred(&g_creds, "admin", "123");
        add_cred(&g_creds, "admin", "pass");
        add_cred(&g_creds, "user", "pass");
    }
    printf("[*] 凭证: %zu组\n", g_creds.count);

    /* 解析端口 */
    PortList ports = parse_ports(port_input);
    if (ports.count == 0) { puts("[!] 无有效端口"); return 1; }

    /* 解析 IP */
    IpList iplist = {0};
    if (is_file(ip_input)) {
        FILE *fp = fopen(ip_input, "r");
        if (!fp) { fprintf(stderr, "[!] 读取失败: %s\n", ip_input); return 1; }
        char line[4096];
        while (fgets(line, sizeof(line), fp)) {
            char *p = trim(line);
            if (*p == 0 || *p == '#') continue;
            char *dup = strdup(p), *tok = strtok(dup, ", \t");
            while (tok) { parse_token_ipv4(&iplist, trim(tok)); tok = strtok(NULL, ", \t"); }
            free(dup);
        }
        fclose(fp);
    } else {
        char *dup = strdup(ip_input), *tok = strtok(dup, ", \t");
        while (tok) { parse_token_ipv4(&iplist, trim(tok)); tok = strtok(NULL, ", \t"); }
        free(dup);
    }

    unsigned long long ip_count = iplist_count(&iplist);
    if (ip_count == 0) { puts("[!] 无有效IP"); return 1; }

    g_total_tasks = ip_count * ports.count;
    printf("[*] 目标: %llu IP × %zu 端口 = %llu 组合\n", ip_count, ports.count, g_total_tasks);
    printf("[*] 并发: %d, 超时: %.1f秒\n", g_max_concurrent, g_timeout);
    puts("[*] 引擎: kqueue 事件驱动 (单线程零拷贝)");

    /* 打开输出文件 */
    g_outfp = fopen(output_input, "w");
    if (!g_outfp) fprintf(stderr, "[!] 无法打开 %s: %s\n", output_input, strerror(errno));

    /* 创建 kqueue */
    int kq = kqueue();
    if (kq < 0) { perror("[!] kqueue"); return 1; }

    puts("[*] 开始扫描...");
    g_start_time = now_sec();

    /* 运行事件循环 */
    IpIter it;
    iptok_init(&it, &iplist);
    event_loop(kq, &it, &ports);

    close(kq);
    print_progress();
    printf("\n");

    double elapsed = now_sec() - g_start_time;
    printf("[*] 完成! 用时: %.2f秒 | 目标: %llu | 发现: %llu\n", elapsed, g_total_tasks, g_found);

    if (g_outfp) {
        fclose(g_outfp);
        if (g_found > 0) printf("[+] 结果: %s\n", output_input);
    }
    if (g_found == 0) puts("[!] 没有发现任何代理");

    /* 清理 */
    free_creds(&g_creds);
    free(iplist.ranges);
    free(ports.ports);
    free(ip_input); free(port_input); free(cred_input);
    free(conns_input); free(timeout_input); free(output_input);

    return 0;
}
