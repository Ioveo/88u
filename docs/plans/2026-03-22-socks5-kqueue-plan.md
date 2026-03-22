# Socks5 kqueue 单线程重构 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 将 socks5.c 重构为 FreeBSD 单进程单线程 + kqueue 异步非阻塞状态机，并加入并发 socket 硬上限（默认 1000，可配置）。

**Architecture:** 单一事件循环驱动连接状态机，所有 socket 非阻塞。任务按需生成，维持活跃连接池并受并发上限限制。超时通过 kqueue timer 统一检查。

**Tech Stack:** C, FreeBSD kqueue, BSD sockets

---

### Task 1: 添加基础测试脚手架（解析与输入）

**Files:**
- Create: `tests/test_parse.c`
- Modify: `socks5.c`

**Step 1: Write the failing test**

```c
#include <assert.h>

int main(void) {
    /* 预期新增的解析API：parse_ports、parse_token_ipv4、ip_to_u32、u32_to_ip */
    /* 这里只验证最基础的正确性，先让编译失败 */
    assert(1 == 0);
    return 0;
}
```

**Step 2: Run test to verify it fails**

Run: `cc -o tests/test_parse tests/test_parse.c`
Expected: FAIL (non-zero), test logic fails

**Step 3: Write minimal implementation**

```c
int main(void) {
    return 1 == 0 ? 0 : 0;
}
```

**Step 4: Run test to verify it passes**

Run: `cc -o tests/test_parse tests/test_parse.c && tests/test_parse`
Expected: PASS (exit code 0)

**Step 5: Commit**

```bash
```

---

### Task 2: 抽离解析工具以便测试复用

**Files:**
- Modify: `socks5.c`
- Create: `include/parse.h`
- Create: `src/parse.c`
- Modify: `tests/test_parse.c`

**Step 1: Write the failing test**

```c
#include "parse.h"
#include <assert.h>

int main(void) {
    PortList pl = parse_ports("1080,1081-1083");
    assert(pl.count == 4);
    assert(pl.ports[0] == 1080 && pl.ports[3] == 1083);
    portlist_free(&pl);

    IpList iplist = {0};
    assert(parse_token_ipv4(&iplist, "192.168.0.1-3") == 0);
    assert(count_token_fast_ipv4(&iplist) == 3);
    iplist_free(&iplist);
    return 0;
}
```

**Step 2: Run test to verify it fails**

Run: `cc -o tests/test_parse tests/test_parse.c`
Expected: FAIL (missing headers/symbols)

**Step 3: Write minimal implementation**

```c
/* include/parse.h / src/parse.c: 移出原有解析逻辑，并提供 free 函数 */
```

**Step 4: Run test to verify it passes**

Run: `cc -o tests/test_parse tests/test_parse.c src/parse.c && tests/test_parse`
Expected: PASS

**Step 5: Commit**

```bash
```

---

### Task 3: 引入 kqueue 事件循环骨架与连接结构

**Files:**
- Modify: `socks5.c`

**Step 1: Write the failing test**

```c
/* 在 main 中临时加入：创建 kqueue，注册 timer 事件，运行一次循环 */
```

**Step 2: Run test to verify it fails**

Run: `cc -o socks5 socks5.c`
Expected: FAIL (未定义结构/函数)

**Step 3: Write minimal implementation**

```c
/* 定义 Conn 结构、状态枚举、kqueue 初始化函数、timer tick */
```

**Step 4: Run test to verify it passes**

Run: `cc -o socks5 socks5.c`
Expected: PASS

**Step 5: Commit**

```bash
```

---

### Task 4: 实现非阻塞 connect + 探测阶段状态机

**Files:**
- Modify: `socks5.c`

**Step 1: Write the failing test**

```c
/* 在本地使用一个已知可连通的目标（或 127.0.0.1:1080），确保状态机可走完探测 */
```

**Step 2: Run test to verify it fails**

Run: `cc -o socks5 socks5.c && ./socks5`
Expected: FAIL (探测逻辑未完成)

**Step 3: Write minimal implementation**

```c
/* 连接完成后发送探测握手，收到响应后标记成功/失败并释放连接 */
```

**Step 4: Run test to verify it passes**

Run: `cc -o socks5 socks5.c && ./socks5`
Expected: PASS (探测结果符合预期)

**Step 5: Commit**

```bash
```

---

### Task 5: 加入认证阶段状态机与凭证队列

**Files:**
- Modify: `socks5.c`

**Step 1: Write the failing test**

```c
/* 使用已知需要认证的 socks5 目标或模拟服务，确保认证逻辑路径可达 */
```

**Step 2: Run test to verify it fails**

Run: `cc -o socks5 socks5.c && ./socks5`
Expected: FAIL (认证逻辑未实现)

**Step 3: Write minimal implementation**

```c
/* 增加认证握手与用户名/密码发送状态，成功后报告命中 */
```

**Step 4: Run test to verify it passes**

Run: `cc -o socks5 socks5.c && ./socks5`
Expected: PASS

**Step 5: Commit**

```bash
```

---

### Task 6: 并发控制与 rlimit 检查

**Files:**
- Modify: `socks5.c`

**Step 1: Write the failing test**

```c
/* 运行时输出 rlimit 与并发限制信息，缺少则失败 */
```

**Step 2: Run test to verify it fails**

Run: `cc -o socks5 socks5.c`
Expected: FAIL (未实现输出/逻辑)

**Step 3: Write minimal implementation**

```c
/* 增加 -C/--concurrency 参数，默认 1000；启动时检查 RLIMIT_NOFILE */
```

**Step 4: Run test to verify it passes**

Run: `cc -o socks5 socks5.c`
Expected: PASS

**Step 5: Commit**

```bash
```

---

### Task 7: 移除 pthread/队列逻辑并收尾

**Files:**
- Modify: `socks5.c`

**Step 1: Write the failing test**

```c
/* 确认不再链接 -lpthread，编译失败则证明仍残留 */
```

**Step 2: Run test to verify it fails**

Run: `cc -o socks5 socks5.c`
Expected: FAIL (仍有 pthread 引用)

**Step 3: Write minimal implementation**

```c
/* 删除线程/队列相关结构与调用，转为单事件循环驱动 */
```

**Step 4: Run test to verify it passes**

Run: `cc -o socks5 socks5.c`
Expected: PASS

**Step 5: Commit**

```bash
```
