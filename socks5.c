/*
 * socks5.c - Socks代理扫描工具 v4.0
 * 支持命令行参数 + 交互式模式 | 支持用户名/密码认证测试
 * Target: FreeBSD x86-64, compile with: cc -o socks5 socks5.c -lpthread
 *
 * 用法:
 *   交互式: ./socks5
 *   命令行: ./socks5 -i check.txt -p 1080 -t 50 -T 5 -o socks.txt -c credentials.txt
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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>

/* ======================== 常量与默认值 ======================== */
#define DEFAULT_PORT       "1080"
#define DEFAULT_CRED_FILE  "credentials.txt"
#define DEFAULT_OUTPUT     "socks.txt"
#define DEFAULT_CHECK      "check.txt"
#define DEFAULT_THREADS    "100"
#define DEFAULT_TIMEOUT    "5"

/* ======================== 数据结构 ======================== */

/* 凭证 */
typedef struct {
    char *user;
    char *pass;
} Cred;

typedef struct {
    Cred  *items;
    size_t count;
    size_t cap;
} CredList;

/* 任务队列 — 仅用于 phase 0 探测 */
typedef struct {
    unsigned int ip;   /* 主机字节序 */
    int          port;
} Task;

typedef struct {
    Task  *buf;
    size_t cap;
    size_t head;
    size_t tail;
    size_t count;
    int    closed;
    pthread_mutex_t lock;
    pthread_cond_t  not_empty;
    pthread_cond_t  not_full;
} TaskQueue;

/* 端口列表 */
typedef struct {
    int   *ports;
    size_t count;
    size_t cap;
} PortList;

/* IP迭代器 token */
typedef struct {
    unsigned int start;
    unsigned int end;
} IpRange;

typedef struct {
    IpRange *ranges;
    size_t   count;
    size_t   cap;
} IpList;

/* 全局状态 */
static volatile int g_stop = 0;
static unsigned long long g_total_tasks = 0;
static unsigned long long g_done_tasks  = 0;
static unsigned long long g_found       = 0;
static unsigned long long g_auth_total  = 0;
static unsigned long long g_auth_done   = 0;
static pthread_mutex_t g_stat_lock = PTHREAD_MUTEX_INITIALIZER;
static FILE *g_outfp = NULL;
static pthread_mutex_t g_out_lock = PTHREAD_MUTEX_INITIALIZER;
static CredList g_creds = {0};
static double g_start_time = 0;

/* ======================== 工具函数 ======================== */

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void on_sigint(int sig) {
    (void)sig;
    g_stop = 1;
}

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
    if (fgets(buf, sizeof(buf), stdin) == NULL)
        return strdup(def);
    char *p = trim(buf);
    if (*p == 0)
        return strdup(def);
    return strdup(p);
}

/* 完整发送，处理 EINTR 和部分发送 */
static int send_all(int fd, const unsigned char *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(fd, buf + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent += n;
    }
    return sent;
}

/* ======================== 凭证管理 ======================== */

static void add_cred(CredList *cl, const char *user, const char *pass) {
    if (cl->count >= cl->cap) {
        cl->cap = cl->cap ? cl->cap * 2 : 16;
        void *tmp = realloc(cl->items, cl->cap * sizeof(Cred));
        if (!tmp) { fprintf(stderr, "[!] realloc failed\n"); return; }
        cl->items = tmp;
    }
    cl->items[cl->count].user = strdup(user);
    cl->items[cl->count].pass = strdup(pass);
    cl->count++;
}

static void free_creds(CredList *cl) {
    for (size_t i = 0; i < cl->count; i++) {
        free(cl->items[i].user);
        free(cl->items[i].pass);
    }
    free(cl->items);
    cl->items = NULL;
    cl->count = cl->cap = 0;
}

static int load_creds(CredList *cl, const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "[!] 加载凭证文件出错: %s\n", path);
        return -1;
    }
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char *p = trim(line);
        if (*p == 0 || *p == '#') continue;
        char *sep = strchr(p, ':');
        if (sep) {
            *sep = 0;
            add_cred(cl, trim(p), trim(sep + 1));
        } else {
            char *sp = strpbrk(p, " \t");
            if (sp) {
                *sp = 0;
                add_cred(cl, trim(p), trim(sp + 1));
            }
        }
    }
    fclose(fp);
    return 0;
}

/* ======================== 任务队列 ======================== */

static int tq_init(TaskQueue *q, size_t cap) {
    q->buf = calloc(cap, sizeof(Task));
    if (!q->buf) return -1;
    q->cap = cap;
    q->head = q->tail = q->count = 0;
    q->closed = 0;
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
    return 0;
}

static void tq_destroy(TaskQueue *q) {
    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->not_empty);
    pthread_cond_destroy(&q->not_full);
    free(q->buf);
    q->buf = NULL;
}

static void tq_push(TaskQueue *q, Task *t) {
    pthread_mutex_lock(&q->lock);
    while (q->count >= q->cap && !q->closed && !g_stop)
        pthread_cond_wait(&q->not_full, &q->lock);
    if (q->closed || g_stop) {
        pthread_mutex_unlock(&q->lock);
        return;
    }
    q->buf[q->tail] = *t;
    q->tail = (q->tail + 1) % q->cap;
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
}

static int tq_pop(TaskQueue *q, Task *t) {
    pthread_mutex_lock(&q->lock);
    while (q->count == 0 && !q->closed)
        pthread_cond_wait(&q->not_empty, &q->lock);
    if (q->count == 0 && q->closed) {
        pthread_mutex_unlock(&q->lock);
        return -1;
    }
    *t = q->buf[q->head];
    q->head = (q->head + 1) % q->cap;
    q->count--;
    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->lock);
    return 0;
}

static void maybe_close_queue(TaskQueue *q) {
    pthread_mutex_lock(&q->lock);
    q->closed = 1;
    pthread_cond_broadcast(&q->not_empty);
    pthread_cond_broadcast(&q->not_full);
    pthread_mutex_unlock(&q->lock);
}

static void queue_task(TaskQueue *q, unsigned int ip, int port) {
    Task t;
    t.ip = ip;
    t.port = port;
    tq_push(q, &t);
}

/* ======================== IP解析 ======================== */

static unsigned int ip_to_u32(const char *s) {
    struct in_addr addr;
    if (inet_pton(AF_INET, s, &addr) != 1) return 0;
    return ntohl(addr.s_addr);
}

static void u32_to_ip(unsigned int ip, char *buf, size_t len) {
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

/* 解析单个IP token: 单IP, CIDR, 或范围 */
static int parse_token_ipv4(IpList *list, const char *token) {
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s", token);

    /* CIDR: 192.168.0.0/24 */
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

    /* 范围: 192.168.0.1-192.168.0.100 */
    char *dash = strchr(tmp, '-');
    if (dash) {
        /* 检查dash后面是否是完整IP */
        if (strchr(dash + 1, '.')) {
            *dash = 0;
            unsigned int s = ip_to_u32(tmp);
            unsigned int e = ip_to_u32(dash + 1);
            if (s == 0 || e == 0 || s > e) return -1;
            iplist_add(list, s, e);
            return 0;
        }
        /* 简写: 192.168.0.1-100 */
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

    /* 单个IP */
    unsigned int ip = ip_to_u32(tmp);
    if (ip == 0 && strcmp(tmp, "0.0.0.0") != 0) return -1;
    iplist_add(list, ip, ip);
    return 0;
}

static unsigned long long count_token_fast_ipv4(IpList *list) {
    unsigned long long total = 0;
    for (size_t i = 0; i < list->count; i++) {
        total += (unsigned long long)(list->ranges[i].end - list->ranges[i].start + 1);
    }
    return total;
}

typedef struct {
    IpList *list;
    size_t  range_idx;
    unsigned int cur_ip;
} IpIter;

static void iptok_init_iter(IpIter *it, IpList *list) {
    it->list = list;
    it->range_idx = 0;
    it->cur_ip = (list->count > 0) ? list->ranges[0].start : 0;
}

static int iptok_next(IpIter *it, unsigned int *out) {
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

/* 解析端口范围字符串 */
static PortList parse_ports(const char *s) {
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
    /* 去重排序 */
    if (pl.count > 1) {
        qsort(pl.ports, pl.count, sizeof(int), cmp_int);
        size_t j = 1;
        for (size_t i = 1; i < pl.count; i++) {
            if (pl.ports[i] != pl.ports[j-1])
                pl.ports[j++] = pl.ports[i];
        }
        pl.count = j;
    }
    return pl;
}

/* ======================== 网络与SOCKS5 ======================== */

static int connect_with_timeout(unsigned int ip, int port, double timeout_sec) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    /* 设置发送/接收超时 */
    struct timeval so_tv;
    so_tv.tv_sec = (long)timeout_sec;
    so_tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &so_tv, sizeof(so_tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &so_tv, sizeof(so_tv));

    /* 设置非阻塞 */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(ip);

    int ret = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (ret == 0) {
        fcntl(fd, F_SETFL, flags); /* 恢复阻塞 */
        return fd;
    }
    if (errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    /* 使用 poll 替代 select，避免 FD_SETSIZE 越界 */
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;

    ret = poll(&pfd, 1, (int)(timeout_sec * 1000));
    if (ret <= 0) {
        close(fd);
        return -1;
    }

    int err = 0;
    socklen_t elen = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
    if (err) {
        close(fd);
        return -1;
    }

    fcntl(fd, F_SETFL, flags);
    return fd;
}

static int sock_send_recv(int fd, const unsigned char *sbuf, int slen,
                          unsigned char *rbuf, int rlen, double timeout_sec) {
    if (send_all(fd, sbuf, slen) < 0) return -1;

    /* 使用 poll 替代 select */
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    int ret = poll(&pfd, 1, (int)(timeout_sec * 1000));
    if (ret <= 0) return -1;

    int n = recv(fd, rbuf, rlen, 0);
    return n;
}

/* 报告发现的代理 */
static void report_hit(unsigned int ip, int port, const char *info) {
    char ipbuf[64];
    u32_to_ip(ip, ipbuf, sizeof(ipbuf));

    pthread_mutex_lock(&g_stat_lock);
    g_found++;
    pthread_mutex_unlock(&g_stat_lock);

    printf("[+] %s:%d -> %s\n", ipbuf, port, info);
    fflush(stdout);

    pthread_mutex_lock(&g_out_lock);
    if (g_outfp) {
        fprintf(g_outfp, "%s:%d -> %s\n", ipbuf, port, info);
        fflush(g_outfp);
    }
    pthread_mutex_unlock(&g_out_lock);
}

/* 格式化剩余时间 */
static void fmt_eta(double secs, char *buf, size_t len) {
    if (secs >= 3600.0)
        snprintf(buf, len, "%.1f时", secs / 3600.0);
    else if (secs >= 60.0)
        snprintf(buf, len, "%.1f分", secs / 60.0);
    else
        snprintf(buf, len, "%.1f秒", secs);
}

/* 进度显示 — 探测进度和认证进度独立显示 */
static void print_progress(void) {
    double elapsed = now_sec() - g_start_time;
    double rate = (g_done_tasks > 0 && elapsed > 0) ? g_done_tasks / elapsed : 0;
    double eta = (rate > 0 && g_total_tasks > g_done_tasks) ?
                 (g_total_tasks - g_done_tasks) / rate : 0;
    char eta_buf[64];
    fmt_eta(eta, eta_buf, sizeof(eta_buf));

    printf("\r%*s\r", 80, "");
    printf("[*] 探测:%llu/%llu(%.1f%%)|认证:%llu/%llu|发现:%llu|用时:%.1f秒|剩余:%s",
           g_done_tasks, g_total_tasks,
           g_total_tasks > 0 ? (double)g_done_tasks / g_total_tasks * 100.0 : 0.0,
           g_auth_done, g_auth_total,
           g_found, elapsed, eta_buf);
    fflush(stdout);
}

/* ======================== 认证逻辑 ======================== */

/*
 * 在当前线程内直接完成所有认证尝试，不推回队列。
 * 避免 P2 死锁问题。
 */
static void try_auth_in_place(unsigned int ip, int port, double timeout) {
    size_t total = g_creds.count;
    pthread_mutex_lock(&g_stat_lock);
    g_auth_total += total;
    pthread_mutex_unlock(&g_stat_lock);

    size_t attempted = 0;

    for (size_t i = 0; i < total && !g_stop; i++) {
        attempted++;
        int fd = connect_with_timeout(ip, port, timeout);
        if (fd < 0) {
            pthread_mutex_lock(&g_stat_lock);
            g_auth_done++;
            pthread_mutex_unlock(&g_stat_lock);
            continue;
        }

        /* 先发送支持用户名密码认证的握手 */
        unsigned char req[4] = {0x05, 0x02, 0x00, 0x02};
        unsigned char resp[2] = {0};
        int n = sock_send_recv(fd, req, 4, resp, 2, timeout);

        if (n == 2 && resp[0] == 0x05 && resp[1] == 0x02) {
            /* 服务器接受用户名/密码认证，发送凭证 */
            Cred *c = &g_creds.items[i];
            int ulen = (int)strlen(c->user);
            int plen = (int)strlen(c->pass);
            unsigned char authbuf[515];
            int alen = 0;
            authbuf[alen++] = 0x01; /* 子协商版本 */
            authbuf[alen++] = (unsigned char)ulen;
            memcpy(authbuf + alen, c->user, ulen); alen += ulen;
            authbuf[alen++] = (unsigned char)plen;
            memcpy(authbuf + alen, c->pass, plen); alen += plen;

            unsigned char aresp[2] = {0};
            n = sock_send_recv(fd, authbuf, alen, aresp, 2, timeout);

            if (n == 2 && aresp[1] == 0x00) {
                char info[256];
                snprintf(info, sizeof(info), "Socks5 (认证成功: %s:%s)", c->user, c->pass);
                report_hit(ip, port, info);
                close(fd);
                pthread_mutex_lock(&g_stat_lock);
                g_auth_done += (total - attempted + 1);
                pthread_mutex_unlock(&g_stat_lock);
                return; /* 找到有效凭证，停止 */
            }
        }

        close(fd);
        pthread_mutex_lock(&g_stat_lock);
        g_auth_done++;
        pthread_mutex_unlock(&g_stat_lock);
    }

    /* 被 g_stop 中断时补齐剩余计数 */
    if (attempted < total) {
        pthread_mutex_lock(&g_stat_lock);
        g_auth_done += (total - attempted);
        pthread_mutex_unlock(&g_stat_lock);
    } else {
        /* 所有凭证都尝试完了且全部失败 */
        report_hit(ip, port, "Socks5 (需要认证但测试凭证无效)");
    }
}

/* ======================== 蜜罐快速检测 ======================== */

/*
 * 对无认证的 SOCKS5 代理做一次 CONNECT 验证
 * 尝试通过代理连接 1.1.1.1:80 并发送 HTTP HEAD 请求
 * 返回: 1=可用代理, 0=蜜罐/不可用
 */
static int verify_proxy(int fd, double timeout) {
    /* SOCKS5 CONNECT 请求到 1.1.1.1:80 */
    unsigned char connect_req[] = {
        0x05, 0x01,                   /* VER, CMD=CONNECT */
        0x00,                         /* RSV */
        0x01,                         /* ATYP=IPv4 */
        0x01, 0x01, 0x01, 0x01,       /* 1.1.1.1 */
        0x00, 0x50                    /* port 80 */
    };
    /*
     * CONNECT 响应最少 10 字节 (VER+REP+RSV+ATYP+ADDR+PORT)
     * 但某些代理返回域名类型 (ATYP=3)，响应会更长，
     * 用更大的缓冲区接收以避免截断
     */
    unsigned char connect_resp[262] = {0};
    int n = sock_send_recv(fd, connect_req, sizeof(connect_req),
                           connect_resp, sizeof(connect_resp), timeout);

    if (n < 4 || connect_resp[0] != 0x05 || connect_resp[1] != 0x00) {
        return 0; /* CONNECT 失败 */
    }

    /* CONNECT 成功，发一个 HTTP HEAD 请求验证连通性 */
    const char *http_req = "HEAD / HTTP/1.0\r\nHost: 1.1.1.1\r\n\r\n";
    unsigned char http_resp[512] = {0};
    n = sock_send_recv(fd, (const unsigned char *)http_req,
                       (int)strlen(http_req), http_resp, sizeof(http_resp) - 1, timeout);

    if (n > 0 && (strstr((char *)http_resp, "HTTP/") != NULL)) {
        return 1; /* 真实可用代理 */
    }

    return 0;
}

/* ======================== Worker线程 ======================== */

static TaskQueue g_queue;
static double g_timeout = 5.0;

static void *worker_main(void *arg) {
    (void)arg;
    Task t;
    while (!g_stop && tq_pop(&g_queue, &t) == 0) {
        if (g_stop) break;

        int fd = connect_with_timeout(t.ip, t.port, g_timeout);
        if (fd < 0) {
            pthread_mutex_lock(&g_stat_lock);
            g_done_tasks++;
            pthread_mutex_unlock(&g_stat_lock);
            continue;
        }

        /*
         * 探测握手: 同时提供 NO AUTH (0x00) 和 USER/PASS (0x02)
         * 这样无论服务器支持哪种认证，都能正确识别
         */
        unsigned char req[4] = {0x05, 0x02, 0x00, 0x02};
        unsigned char resp[2] = {0};
        int n = sock_send_recv(fd, req, 4, resp, 2, g_timeout);

        if (n == 2 && resp[0] == 0x05) {
            if (resp[1] == 0x00) {
                /* 无需认证 — 做一次代理可用性验证 */
                if (verify_proxy(fd, g_timeout)) {
                    report_hit(t.ip, t.port, "Socks5 (已验证)");
                }
                /* 验证失败的不报告，避免蜂罐和无效代理污染结果 */
            } else if (resp[1] == 0x02) {
                /* 需要用户名/密码认证 — 在当前线程内直接完成 */
                close(fd);
                fd = -1; /* 标记已关闭 */
                if (g_creds.count > 0) {
                    try_auth_in_place(t.ip, t.port, g_timeout);
                } else {
                    report_hit(t.ip, t.port, "Socks5 (需要认证但无可用测试凭证)");
                }
            } else if (resp[1] == 0xFF) {
                /* 不接受提供的任何方法 — 不报告 */
            } else {
                char info[128];
                snprintf(info, sizeof(info), "Socks5 (未知认证方式: 0x%02x)", resp[1]);
                report_hit(t.ip, t.port, info);
            }
        }

        if (fd >= 0) close(fd);

        pthread_mutex_lock(&g_stat_lock);
        g_done_tasks++;
        pthread_mutex_unlock(&g_stat_lock);
    }
    return NULL;
}

/* ======================== 主函数 ======================== */

static void print_banner(void) {
    puts("\n============================================================");
    puts("   _____  ____  __  __ ____  _____  _______     _______ ______ _      _____ ");
    puts("  / ____|/ __ \\|  \\/  |  _ \\|  __ \\|  __ \\ \\   / / ____|  ____| |    |_   _|");
    puts(" | (___ | |  | | \\  / | |_) | |__) | |__) \\ \\_/ / |  __| |__  | |      | |  ");
    puts("  \\___ \\| |  | | |\\/| |  _ <|  _  /|  ___/ \\   /| | |_ |  __| | |      | |  ");
    puts("  ____) | |__| | |  | | |_) | | \\ \\| |      | | | |__| | |____| |____ _| |_ ");
    puts(" |_____/ \\____/|_|  |_|____/|_|  \\_\\_|      |_|  \\_____|______|______|_____|");
    puts("  Socks代理扫描工具 v4.0 | 命令行+交互式 | 支持代理验证");
    puts("============================================================\n");
}

static void print_usage(const char *prog) {
    printf("用法: %s [选项]\n", prog);
    puts("  -i <IP/文件>      IP地址范围或包含IP列表的文件 (默认: check.txt)");
    puts("  -p <端口>         端口范围 (默认: 1080)");
    puts("  -c <凭证文件>     凭证文件路径 (默认: credentials.txt)");
    puts("  -t <线程数>       并发线程数 (默认: 100)");
    puts("  -T <超时>         连接超时时间/秒 (默认: 5)");
    puts("  -o <输出文件>     结果输出文件 (默认: socks.txt)");
    puts("  -h                显示此帮助信息");
    puts("\n示例:");
    puts("  ./socks5 -i 192.168.1.0/24 -p 1080,8080 -t 50 -T 3 -o result.txt");
    puts("  ./socks5 -i check.txt -c creds.txt");
    puts("  ./socks5  (交互式模式)");
}

int main(int argc, char *argv[]) {
    signal(SIGINT, on_sigint);
    signal(SIGPIPE, SIG_IGN); /* 忽略 SIGPIPE，避免写入已关闭的 socket 时崩溃 */

    char *ip_input = NULL;
    char *port_input = NULL;
    char *cred_input = NULL;
    char *thread_input = NULL;
    char *timeout_input = NULL;
    char *output_input = NULL;
    int interactive = 1;

    /* 命令行参数解析 */
    int opt;
    while ((opt = getopt(argc, argv, "i:p:c:t:T:o:h")) != -1) {
        interactive = 0;
        switch (opt) {
            case 'i': ip_input = strdup(optarg); break;
            case 'p': port_input = strdup(optarg); break;
            case 'c': cred_input = strdup(optarg); break;
            case 't': thread_input = strdup(optarg); break;
            case 'T': timeout_input = strdup(optarg); break;
            case 'o': output_input = strdup(optarg); break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    print_banner();

    if (interactive) {
        /* 交互式输入 */
        puts("提示:");
        puts("- 按回车键使用默认值");
        puts("- IP地址范围支持: 单个IP, CIDR格式 (192.168.0.0/24), IP范围 (192.168.0.1-192.168.0.100)");
        puts("- 或者直接输入包含IP列表的文件路径");
        puts("- 凭证文件格式: 每行 username password / username:password\n");

        ip_input      = get_input("IP地址范围(或文件路径)", DEFAULT_CHECK);
        port_input    = get_input("端口范围", DEFAULT_PORT);
        cred_input    = get_input("凭证文件路径", DEFAULT_CRED_FILE);
        thread_input  = get_input("并发线程数", DEFAULT_THREADS);
        timeout_input = get_input("连接超时时间(秒)", DEFAULT_TIMEOUT);
        output_input  = get_input("结果输出文件", DEFAULT_OUTPUT);
    } else {
        /* 填充默认值 */
        if (!ip_input)      ip_input = strdup(DEFAULT_CHECK);
        if (!port_input)    port_input = strdup(DEFAULT_PORT);
        if (!cred_input)    cred_input = strdup(DEFAULT_CRED_FILE);
        if (!thread_input)  thread_input = strdup(DEFAULT_THREADS);
        if (!timeout_input) timeout_input = strdup(DEFAULT_TIMEOUT);
        if (!output_input)  output_input = strdup(DEFAULT_OUTPUT);
    }

    /* 解析线程数和超时 */
    long nthreads = strtol(thread_input, NULL, 10);
    g_timeout = strtod(timeout_input, NULL);
    if (nthreads <= 0 || g_timeout <= 0) {
        fprintf(stderr, "[!] 无效的线程数或超时时间，使用默认值 (线程=%s, 超时=%s)\n",
                DEFAULT_THREADS, DEFAULT_TIMEOUT);
        nthreads = strtol(DEFAULT_THREADS, NULL, 10);
        g_timeout = strtod(DEFAULT_TIMEOUT, NULL);
    }

    /* 检查文件描述符限制，自动调整线程数 */
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        long max_safe = (long)(rl.rlim_cur * 0.7); /* 留 30% 余量 */
        if (max_safe < 10) max_safe = 10;
        if (nthreads > max_safe) {
            printf("[!] 文件描述符限制 %llu，自动调整线程数: %ld -> %ld\n",
                   (unsigned long long)rl.rlim_cur, nthreads, max_safe);
            nthreads = max_safe;
        }
    }

    /* 加载凭证 */
    if (is_file(cred_input)) {
        if (load_creds(&g_creds, cred_input) < 0) {
            /* 使用默认凭证 */
        }
    } else {
        fprintf(stderr, "[!] 警告: 凭证文件 %s 不存在，使用默认凭证\n", cred_input);
    }
    /* 如果没有加载到凭证，添加默认凭证 */
    if (g_creds.count == 0) {
        add_cred(&g_creds, "admin", "123");
        add_cred(&g_creds, "admin", "pass");
        add_cred(&g_creds, "user", "pass");
    }
    printf("[*] 已加载凭证: %zu组\n", g_creds.count);

    /* 解析端口 */
    PortList ports = parse_ports(port_input);
    if (ports.count == 0) {
        puts("[!] 错误: 未获取到有效的端口");
        return 1;
    }

    /* 解析IP */
    IpList iplist = {0};
    if (is_file(ip_input)) {
        FILE *fp = fopen(ip_input, "r");
        if (!fp) {
            fprintf(stderr, "[!] 读取IP文件出错: %s\n", ip_input);
            return 1;
        }
        char line[4096];
        while (fgets(line, sizeof(line), fp)) {
            char *p = trim(line);
            if (*p == 0 || *p == '#') continue;
            /* 按逗号和空格分割 */
            char *dup = strdup(p);
            char *tok = strtok(dup, ", \t");
            while (tok) {
                parse_token_ipv4(&iplist, trim(tok));
                tok = strtok(NULL, ", \t");
            }
            free(dup);
        }
        fclose(fp);
    } else {
        /* 直接解析输入 */
        char *dup = strdup(ip_input);
        char *tok = strtok(dup, ", \t");
        while (tok) {
            parse_token_ipv4(&iplist, trim(tok));
            tok = strtok(NULL, ", \t");
        }
        free(dup);
    }

    unsigned long long ip_count = count_token_fast_ipv4(&iplist);
    if (ip_count == 0) {
        puts("[!] 错误: 未获取到有效的IP地址（或无法统计数量）");
        return 1;
    }

    g_total_tasks = ip_count * ports.count;
    printf("[*] 端口探测目标: %llu个IP地址, %zu个端口, 共%llu个组合\n",
           ip_count, ports.count, g_total_tasks);
    puts("[*] 策略: SOCKS5握手探测 -> 无认证代理验证连通性 -> 认证代理在线程内直接尝试凭证");
    printf("[*] 使用线程: %ld, 超时: %.2f秒\n", nthreads, g_timeout);

    /* 打开输出文件 */
    g_outfp = fopen(output_input, "w");
    if (!g_outfp) {
        fprintf(stderr, "[!] 警告: 无法打开输出文件 %s 进行实时写入: %s\n",
                output_input, strerror(errno));
    }

    /* 初始化任务队列 */
    size_t qcap = (size_t)(nthreads * 4);
    if (qcap < 1024) qcap = 1024;
    if (tq_init(&g_queue, qcap) < 0) {
        puts("[!] 初始化任务队列失败");
        return 1;
    }

    puts("[*] 开始扫描...");
    g_start_time = now_sec();

    /* 创建工作线程 */
    pthread_t *threads = malloc(nthreads * sizeof(pthread_t));
    if (!threads) {
        puts("[!] 分配线程资源失败");
        return 1;
    }
    for (long i = 0; i < nthreads; i++) {
        pthread_create(&threads[i], NULL, worker_main, NULL);
    }

    /* 生产者: 枚举所有IP:Port组合 */
    IpIter it;
    iptok_init_iter(&it, &iplist);
    unsigned int cur_ip;
    unsigned long long enqueued = 0;
    double last_progress = 0;

    while (!g_stop && iptok_next(&it, &cur_ip)) {
        for (size_t pi = 0; pi < ports.count && !g_stop; pi++) {
            queue_task(&g_queue, cur_ip, ports.ports[pi]);
            enqueued++;
            double now = now_sec();
            if (now - last_progress >= 2.0) { /* 每2秒刷新进度 */
                print_progress();
                last_progress = now;
            }
        }
    }

    /* 关闭队列 */
    maybe_close_queue(&g_queue);

    /* 等待所有线程完成 */
    for (long i = 0; i < nthreads; i++) {
        pthread_join(threads[i], NULL);
    }

    print_progress();
    printf("\n");

    double elapsed = now_sec() - g_start_time;
    printf("[*] 扫描完成! 用时: %.2f秒\n", elapsed);
    printf("[*] 扫描目标: %llu个, 认证尝试: %llu个, 发现代理: %llu个\n",
           g_total_tasks, g_auth_total, g_found);

    /* 保存结果 */
    if (g_outfp) {
        fclose(g_outfp);
        if (g_found > 0) {
            printf("[+] 结果已保存至 %s\n", output_input);
        }
    } else {
        if (g_found > 0) {
            puts("[!] 结果未能实时写入（输出文件打开失败）");
        }
    }

    if (g_found == 0) {
        puts("[!] 没有发现任何代理");
    }

    /* 清理 */
    free(threads);
    tq_destroy(&g_queue);
    free_creds(&g_creds);
    free(iplist.ranges);
    free(ports.ports);
    free(ip_input);
    free(port_input);
    free(cred_input);
    free(thread_input);
    free(timeout_input);
    free(output_input);

    return 0;
}
