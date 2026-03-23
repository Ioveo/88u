/*
 * socks5.c - Socks代理扫描工具 v3.5
 * 交互式模式 | 支持用户名/密码认证测试
 * Target: FreeBSD x86-64, compile with: cc -o socks5 socks5.c src/parse.c src/socks5_proto.c
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
#include <sys/event.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "include/parse.h"
#include "include/socks5_proto.h"

/* ======================== 常量与默认值 ======================== */
#define DEFAULT_PORT       "1080"
#define DEFAULT_CRED_FILE  "credentials.txt"
#define DEFAULT_OUTPUT     "socks.txt"
#define DEFAULT_CHECK      "check.txt"
#define DEFAULT_TIMEOUT    "5"
#define DEFAULT_KQUEUE_CONCURRENCY 1000
#define KQUEUE_RLIMIT_MARGIN 50

/* ======================== 数据结构 ======================== */

typedef enum {
    CONN_ST_UNUSED = 0,
    CONN_ST_CONNECTING,
    CONN_ST_PROBE_SEND,
    CONN_ST_PROBE_RECV,
    CONN_ST_AUTH_SEND,
    CONN_ST_AUTH_RECV,
    CONN_ST_DONE,
    CONN_ST_FAILED
} ConnState;

typedef struct {
    int fd;
    unsigned int ip;
    int port;
    int phase;
    int cred_idx;
    ConnState state;
    double start_ts;
    double last_io_ts;
    unsigned char rbuf[512];
    size_t rlen;
    unsigned char sbuf[512];
    size_t slen;
    size_t soff;
    int want_read;
    int want_write;
} Conn;

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

/* 全局状态 */
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

/* ======================== 凭证管理 ======================== */

static void add_cred(CredList *cl, const char *user, const char *pass) {
    if (cl->count >= cl->cap) {
        cl->cap = cl->cap ? cl->cap * 2 : 16;
        cl->items = realloc(cl->items, cl->cap * sizeof(Cred));
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

/* ======================== 网络与SOCKS5 ======================== */

/* 报告发现的代理 */
static void report_hit(unsigned int ip, int port, const char *info) {
    char ipbuf[64];
    u32_to_ip(ip, ipbuf, sizeof(ipbuf));

    g_found++;

    printf("[+] %s:%d -> %s\n", ipbuf, port, info);
    fflush(stdout);

    if (g_outfp) {
        fprintf(g_outfp, "%s:%d -> %s\n", ipbuf, port, info);
        fflush(g_outfp);
    }
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

/* 进度显示 */
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

/* ======================== kqueue 事件循环骨架 ======================== */

static int kq_init(void) {
    int kq = kqueue();
    return kq;
}

static int kq_update_conn_events(int kq, Conn *c, int want_read, int want_write) {
    struct kevent evs[2];
    int n = 0;

    if (want_read != c->want_read) {
        EV_SET(&evs[n++], (uintptr_t)c->fd, EVFILT_READ,
               want_read ? (EV_ADD | EV_ENABLE) : EV_DELETE,
               0, 0, c);
        c->want_read = want_read;
    }
    if (want_write != c->want_write) {
        EV_SET(&evs[n++], (uintptr_t)c->fd, EVFILT_WRITE,
               want_write ? (EV_ADD | EV_ENABLE) : EV_DELETE,
               0, 0, c);
        c->want_write = want_write;
    }

    if (n == 0) return 0;
    return kevent(kq, evs, n, NULL, 0, NULL);
}

static void stats_add_done(unsigned long long done, unsigned long long auth_done) {
    g_done_tasks += done;
    g_auth_done += auth_done;
}

static void stats_add_auth_total(unsigned long long count) {
    g_auth_total += count;
    g_total_tasks += count;
}

static int conn_prepare_hello(Conn *c) {
    size_t len = socks5_build_hello(c->sbuf, sizeof(c->sbuf), g_creds.count > 0);
    if (len == 0) return -1;
    c->slen = len;
    c->soff = 0;
    return 0;
}

static int conn_prepare_auth_payload(Conn *c, const Cred *cred) {
    int alen = socks5_build_auth(c->sbuf, sizeof(c->sbuf), cred->user, cred->pass);
    if (alen < 0) return -1;
    c->slen = (size_t)alen;
    c->soff = 0;
    return 0;
}

static void conn_reset(Conn *c) {
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    c->state = CONN_ST_UNUSED;
    c->rlen = 0;
    c->slen = 0;
    c->soff = 0;
    c->want_read = 0;
    c->want_write = 0;
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;
    return 0;
}

static int conn_start(Conn *c, unsigned int ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (set_nonblocking(fd) < 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(ip);

    int ret = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (ret < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    c->fd = fd;
    c->ip = ip;
    c->port = port;
    c->phase = 0;
    c->cred_idx = -1;
    c->start_ts = now_sec();
    c->last_io_ts = c->start_ts;
    c->rlen = 0;
    if (conn_prepare_hello(c) < 0) {
        close(fd);
        return -1;
    }
    c->want_read = 0;
    c->want_write = 0;

    if (ret == 0) {
        c->state = CONN_ST_PROBE_SEND;
    } else {
        c->state = CONN_ST_CONNECTING;
    }
    return 0;
}

static void conn_finish(int kq, Conn *c, int success) {
    (void)success;
    kq_update_conn_events(kq, c, 0, 0);
    conn_reset(c);
}

static void conn_auth_finalize(Conn *c, int report_invalid) {
    if (g_creds.count == 0) return;
    if (c->cred_idx < 0) return;
    if ((size_t)c->cred_idx >= g_creds.count) return;
    stats_add_done(g_creds.count - (size_t)c->cred_idx,
                   g_creds.count - (size_t)c->cred_idx);
    if (report_invalid) {
        report_hit(c->ip, c->port, "Socks5 (需要认证但测试凭证无效)");
    }
}

static int next_target(IpIter *it, PortList *ports, unsigned int *cur_ip,
                       size_t *port_idx, int *has_ip,
                       unsigned int *ip_out, int *port_out) {
    if (!*has_ip || ports->count == 0) return 0;
    *ip_out = *cur_ip;
    *port_out = ports->ports[*port_idx];
    (*port_idx)++;
    if (*port_idx >= ports->count) {
        *port_idx = 0;
        *has_ip = iptok_next(it, cur_ip);
    }
    return 1;
}

static void run_kqueue_probe(IpList *iplist, PortList *ports, size_t max_active) {
    int kq = kq_init();
    if (kq < 0) {
        fprintf(stderr, "[!] kqueue init failed: %s\n", strerror(errno));
        return;
    }

    Conn *conns = calloc(max_active, sizeof(Conn));
    if (!conns) {
        fprintf(stderr, "[!] alloc conns failed\n");
        close(kq);
        return;
    }
    for (size_t i = 0; i < max_active; i++) {
        conns[i].fd = -1;
        conns[i].state = CONN_ST_UNUSED;
    }

    IpIter it;
    iptok_init_iter(&it, iplist);
    unsigned int cur_ip = 0;
    int has_ip = iptok_next(&it, &cur_ip);
    size_t port_idx = 0;
    size_t active = 0;
    double last_progress = 0;

    while (!g_stop && (active > 0 || has_ip)) {
        while (!g_stop && active < max_active) {
            unsigned int ip;
            int port;
            if (!next_target(&it, ports, &cur_ip, &port_idx, &has_ip, &ip, &port))
                break;

            Conn *slot = NULL;
            for (size_t i = 0; i < max_active; i++) {
                if (conns[i].state == CONN_ST_UNUSED) {
                    slot = &conns[i];
                    break;
                }
            }
            if (!slot) break;

            if (conn_start(slot, ip, port) < 0) {
                g_done_tasks++;
                continue;
            }

            active++;
            if (slot->state == CONN_ST_CONNECTING || slot->state == CONN_ST_PROBE_SEND) {
                kq_update_conn_events(kq, slot, 0, 1);
            }
        }

        struct kevent events[64];
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 100000000;

        int nev = kevent(kq, NULL, 0, events, (int)(sizeof(events) / sizeof(events[0])), &ts);
        if (nev < 0 && errno != EINTR) {
            fprintf(stderr, "[!] kevent error: %s\n", strerror(errno));
            break;
        }

        for (int i = 0; i < nev; i++) {
            Conn *c = (Conn *)events[i].udata;
            if (!c || c->state == CONN_ST_UNUSED) continue;

            if (events[i].flags & (EV_ERROR | EV_EOF)) {
                if (c->cred_idx >= 0) {
                    conn_auth_finalize(c, 0);
                } else {
                    stats_add_done(1, 0);
                }
                conn_finish(kq, c, 0);
                active--;
                continue;
            }

            if (events[i].filter == EVFILT_WRITE) {
                if (c->state == CONN_ST_CONNECTING) {
                    int err = 0;
                    socklen_t elen = sizeof(err);
                    if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err != 0) {
                        stats_add_done(1, 0);
                        conn_finish(kq, c, 0);
                        active--;
                        continue;
                    }
                    c->state = CONN_ST_PROBE_SEND;
                }

                if (c->state == CONN_ST_PROBE_SEND) {
                    ssize_t n = send(c->fd, c->sbuf + c->soff, c->slen - c->soff, 0);
                    if (n > 0) {
                        c->soff += (size_t)n;
                        c->last_io_ts = now_sec();
                        if (c->soff >= c->slen) {
                            c->state = CONN_ST_PROBE_RECV;
                            c->rlen = 0;
                            kq_update_conn_events(kq, c, 1, 0);
                        }
                    } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                        stats_add_done(1, 0);
                        conn_finish(kq, c, 0);
                        active--;
                    }
                } else if (c->state == CONN_ST_AUTH_SEND) {
                    ssize_t n = send(c->fd, c->sbuf + c->soff, c->slen - c->soff, 0);
                    if (n > 0) {
                        c->soff += (size_t)n;
                        c->last_io_ts = now_sec();
                        if (c->soff >= c->slen) {
                            c->state = CONN_ST_AUTH_RECV;
                            c->rlen = 0;
                            kq_update_conn_events(kq, c, 1, 0);
                        }
                    } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                        conn_auth_finalize(c, 0);
                        conn_finish(kq, c, 0);
                        active--;
                    }
                }
            } else if (events[i].filter == EVFILT_READ) {
                if (c->state == CONN_ST_PROBE_RECV) {
                    ssize_t n = recv(c->fd, c->rbuf + c->rlen, 2 - c->rlen, 0);
                    if (n > 0) {
                        c->rlen += (size_t)n;
                        c->last_io_ts = now_sec();
                        if (c->rlen >= 2) {
                            int finish_conn = 1;
                            if (c->rbuf[0] == 0x05) {
                                if (c->rbuf[1] == 0x00) {
                                    report_hit(c->ip, c->port, "Socks5 (无需认证)");
                                } else if (c->rbuf[1] == 0x02) {
                                    if (g_creds.count > 0) {
                                        stats_add_auth_total(g_creds.count);
                                        c->cred_idx = 0;
                                        if (conn_prepare_auth_payload(c, &g_creds.items[c->cred_idx]) < 0) {
                                            conn_auth_finalize(c, 1);
                                            conn_finish(kq, c, 0);
                                            active--;
                                            finish_conn = 0;
                                            break;
                                        }
                                        c->state = CONN_ST_AUTH_SEND;
                                        c->rlen = 0;
                                        finish_conn = 0;
                                        kq_update_conn_events(kq, c, 0, 1);
                                    } else {
                                        report_hit(c->ip, c->port, "Socks5 (需要认证但无可用测试凭证)");
                                    }
                                } else if (c->rbuf[1] == 0xFF) {
                                    /* no acceptable method */
                                } else {
                                    char info[128];
                                    snprintf(info, sizeof(info), "Socks5 (未知认证方式: 0x%02x)", c->rbuf[1]);
                                    report_hit(c->ip, c->port, info);
                                }
                            }

                            stats_add_done(1, 0);
                            if (finish_conn) {
                                conn_finish(kq, c, 1);
                                active--;
                            }
                        }
                    } else if (n == 0) {
                        stats_add_done(1, 0);
                        conn_finish(kq, c, 0);
                        active--;
                    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        stats_add_done(1, 0);
                        conn_finish(kq, c, 0);
                        active--;
                    }
                } else if (c->state == CONN_ST_AUTH_RECV) {
                    ssize_t n = recv(c->fd, c->rbuf + c->rlen, 2 - c->rlen, 0);
                    if (n > 0) {
                        c->rlen += (size_t)n;
                        c->last_io_ts = now_sec();
                        if (c->rlen >= 2) {
                            if (c->rbuf[0] == 0x01 && c->rbuf[1] == 0x00) {
                                char info[256];
                                Cred *cred = &g_creds.items[c->cred_idx];
                                snprintf(info, sizeof(info), "Socks5 (认证成功: %s:%s)", cred->user, cred->pass);
                                report_hit(c->ip, c->port, info);
                                stats_add_done(g_creds.count - (size_t)c->cred_idx,
                                               g_creds.count - (size_t)c->cred_idx);
                                conn_finish(kq, c, 1);
                                active--;
                            } else {
                                stats_add_done(1, 1);
                                if ((size_t)c->cred_idx + 1 < g_creds.count) {
                                    c->cred_idx++;
                                    if (conn_prepare_auth_payload(c, &g_creds.items[c->cred_idx]) < 0) {
                                        conn_auth_finalize(c, 1);
                                        conn_finish(kq, c, 0);
                                        active--;
                                        break;
                                    }
                                    c->state = CONN_ST_AUTH_SEND;
                                    c->rlen = 0;
                                    kq_update_conn_events(kq, c, 0, 1);
                                } else {
                                    report_hit(c->ip, c->port, "Socks5 (需要认证但测试凭证无效)");
                                    conn_finish(kq, c, 0);
                                    active--;
                                }
                            }
                        }
                    } else if (n == 0) {
                        conn_auth_finalize(c, 0);
                        conn_finish(kq, c, 0);
                        active--;
                    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        conn_auth_finalize(c, 0);
                        conn_finish(kq, c, 0);
                        active--;
                    }
                }
            }
        }

        double now = now_sec();
        for (size_t i = 0; i < max_active; i++) {
            Conn *c = &conns[i];
            if (c->state == CONN_ST_UNUSED) continue;
            if (now - c->last_io_ts <= g_timeout) continue;
            if (c->cred_idx >= 0) {
                conn_auth_finalize(c, 0);
            } else {
                stats_add_done(1, 0);
            }
            conn_finish(kq, c, 0);
            if (active > 0) active--;
        }
        if (now - last_progress >= 0.5) {
            print_progress();
            last_progress = now;
        }
    }

    for (size_t i = 0; i < max_active; i++) {
        if (conns[i].state != CONN_ST_UNUSED) {
            conn_finish(kq, &conns[i], 0);
        }
    }

    free(conns);
    close(kq);
}

/* ======================== 主函数 ======================== */

static void print_banner(void) {
    puts("\n============================================================");
    puts("   _____  ____  __  __ ____  _____  _______     _______ ______ _      _____ ");
    puts("  / ____|/ __ \|  \/  |  _ \|  __ \|  __ \ \   / / ____|  ____| |    |_   _|");
    puts(" | (___ | |  | | \  / | |_) | |__) | |__) \ \_/ / |  __| |__  | |      | |  ");
    puts("  \___ \| |  | | |\/| |  _ <|  _  /|  ___/ \   /| | |_ |  __| | |      | |  ");
    puts("  ____) | |__| | |  | | |_) | | \ \| |      | | | |__| | |____| |____ _| |_ ");
    puts(" |_____/ \____/|_|  |_|____/|_|  \_\_|      |_|  \_____|______|______|_____|");
    puts("  Socks代理扫描工具 v3.5 | 交互式模式 | 支持用户名/密码认证测试");
    puts("============================================================\n");
}

int main(int argc, char **argv) {
    signal(SIGINT, on_sigint);

    size_t kq_concurrency = DEFAULT_KQUEUE_CONCURRENCY;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-C") == 0 || strcmp(argv[i], "--concurrency") == 0) {
            if (i + 1 < argc) {
                char *endp = NULL;
                long val = strtol(argv[++i], &endp, 10);
                if (endp && *endp == '\0' && val > 0) {
                    kq_concurrency = (size_t)val;
                } else {
                    fprintf(stderr, "[!] invalid concurrency value, using default %d\n",
                            DEFAULT_KQUEUE_CONCURRENCY);
                }
            } else {
                fprintf(stderr, "[!] missing value for --concurrency, using default %d\n",
                        DEFAULT_KQUEUE_CONCURRENCY);
            }
        } else if (strncmp(argv[i], "--concurrency=", 14) == 0) {
            char *valstr = argv[i] + 14;
            char *endp = NULL;
            long val = strtol(valstr, &endp, 10);
            if (endp && *endp == '\0' && val > 0) {
                kq_concurrency = (size_t)val;
            } else {
                fprintf(stderr, "[!] invalid concurrency value, using default %d\n",
                        DEFAULT_KQUEUE_CONCURRENCY);
            }
        } else if (strcmp(argv[i], "-T") == 0 || strcmp(argv[i], "--timeout") == 0) {
            if (i + 1 < argc) {
                char *endp = NULL;
                double val = strtod(argv[++i], &endp);
                if (endp && *endp == '\0' && val > 0) {
                    g_timeout = val;
                } else {
                    fprintf(stderr, "[!] invalid timeout value, using default %s\n",
                            DEFAULT_TIMEOUT);
                    g_timeout = strtod(DEFAULT_TIMEOUT, NULL);
                }
            } else {
                fprintf(stderr, "[!] missing value for --timeout, using default %s\n",
                        DEFAULT_TIMEOUT);
                g_timeout = strtod(DEFAULT_TIMEOUT, NULL);
            }
        } else if (strncmp(argv[i], "--timeout=", 10) == 0) {
            char *valstr = argv[i] + 10;
            char *endp = NULL;
            double val = strtod(valstr, &endp);
            if (endp && *endp == '\0' && val > 0) {
                g_timeout = val;
            } else {
                fprintf(stderr, "[!] invalid timeout value, using default %s\n",
                        DEFAULT_TIMEOUT);
                g_timeout = strtod(DEFAULT_TIMEOUT, NULL);
            }
        }
    }

    print_banner();

    /* 提示信息 */
    puts("提示:");
    puts("- 按回车键使用默认值");
    puts("- IP地址范围支持: 单个IP, CIDR格式 (192.168.0.0/24), IP范围 (192.168.0.1-192.168.0.100)");
    puts("- 或者直接输入包含IP列表的文件路径");
    puts("- 凭证文件格式: 每行 username password / username:password\n");

    /* 交互式输入 */
    char *ip_input   = get_input("IP地址范围(或文件路径)", DEFAULT_CHECK);
    char *port_input  = get_input("端口范围", DEFAULT_PORT);
    char *cred_input  = get_input("凭证文件路径", DEFAULT_CRED_FILE);
    char timeout_default[32];
    snprintf(timeout_default, sizeof(timeout_default), "%.2f", g_timeout);
    char *timeout_input = get_input("连接超时时间(秒)", timeout_default);
    char concurrency_default[32];
    snprintf(concurrency_default, sizeof(concurrency_default), "%zu", kq_concurrency);
    char *concurrency_input = get_input("并发连接数", concurrency_default);
    char *output_input = get_input("结果输出文件", DEFAULT_OUTPUT);

    /* 解析并发连接数 */
    {
        char *endp = NULL;
        long val = strtol(concurrency_input, &endp, 10);
        if (endp && *endp == '\0' && val > 0) {
            kq_concurrency = (size_t)val;
        } else {
            fprintf(stderr, "[!] 无效的并发连接数，使用默认值 (%d)\n",
                    DEFAULT_KQUEUE_CONCURRENCY);
            kq_concurrency = DEFAULT_KQUEUE_CONCURRENCY;
        }
    }

    /* 解析超时 */
    {
        char *endp = NULL;
        double val = strtod(timeout_input, &endp);
        if (endp && *endp == '\0' && val > 0) {
            g_timeout = val;
        } else {
            fprintf(stderr, "[!] 无效的超时时间，使用默认值 (%s)\n", DEFAULT_TIMEOUT);
            g_timeout = strtod(DEFAULT_TIMEOUT, NULL);
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
    printf("[*] 已加载凭证: %zu组 | 可用于测试: %zu组\n", g_creds.count, g_creds.count);

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
    puts("[*] 策略: 先做端口/SOCKS5握手探测, 仅对可达且要求认证的端口逐个尝试用户名密码");
    printf("[*] 并发连接: %zu, 超时: %.2f秒\n", kq_concurrency, g_timeout);

    /* 打开输出文件 */
    g_outfp = fopen(output_input, "w");
    if (!g_outfp) {
        fprintf(stderr, "[!] 警告: 无法打开输出文件 %s 进行实时写入: %s\n",
                output_input, strerror(errno));
    }

    puts("[*] 开始扫描...");
    g_start_time = now_sec();

    {
        size_t max_active = kq_concurrency;
        if (max_active < 1) max_active = 1;
        struct rlimit rl;
        if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY) {
            rlim_t need = (rlim_t)(kq_concurrency + KQUEUE_RLIMIT_MARGIN);
            if (rl.rlim_cur < need) {
                fprintf(stderr,
                        "[!] warning: RLIMIT_NOFILE soft=%llu < concurrency+margin (%zu+%d)\n",
                        (unsigned long long)rl.rlim_cur, kq_concurrency, KQUEUE_RLIMIT_MARGIN);
            }
        }
        run_kqueue_probe(&iplist, &ports, max_active);
    }

    print_progress();
    printf("\n");

    double elapsed = now_sec() - g_start_time;
    printf("[*] 扫描完成! 用时: %.2f秒\n", elapsed);
    printf("[*] 扫描目标: %llu个, 发现代理: %llu个\n", g_total_tasks, g_found);

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
    free_creds(&g_creds);
    iplist_free(&iplist);
    portlist_free(&ports);
    free(ip_input);
    free(port_input);
    free(cred_input);
    free(timeout_input);
    free(concurrency_input);
    free(output_input);

    puts("\n按回车键退出...");
    getc(stdin);

    return 0;
}
