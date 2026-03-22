# Socks5 Scanner kqueue 单线程重构设计

## 背景与目标

当前实现使用 pthread + select，在 FreeBSD 的受限环境（SERV00）下存在明显资源浪费。目标是将工具完全重构为单进程单线程、基于 kqueue 的异步非阻塞 I/O 状态机架构，同时严格限制并发 socket 数量（硬上限 1000），以降低被系统限制或 kill 的风险。

## 约束

- 运行环境：FreeBSD（SERV00）。
- 进程/线程数上限严格，禁止使用 pthread。
- 必须使用 kqueue。
- 并发 socket 数量硬上限 1000（可配置）。

## 架构与组件

- 单进程单线程，核心为 kqueue 事件循环。
- 所有 socket 使用非阻塞模式。
- 连接生命周期由状态机驱动，状态包括：
  - ST_CONNECTING
  - ST_PROBE_SEND
  - ST_PROBE_RECV
  - ST_AUTH_HELLO_SEND
  - ST_AUTH_HELLO_RECV
  - ST_AUTH_SEND
  - ST_AUTH_RECV
  - ST_DONE / ST_FAILED
- 任务来源仍是 IP×Port 组合，但由迭代器按需生成，不提前展开全部任务。

## 数据流

1. 启动时解析 IP 列表、端口范围、凭证文件与并发参数。
2. 事件循环维持“活跃连接池”，当活跃连接数低于并发上限时，从任务迭代器取新的 IP:Port 任务。
3. 每个连接维护自身状态、缓冲区、计时信息。
4. kqueue 监听：
   - EVFILT_WRITE：连接完成及发送阶段触发。
   - EVFILT_READ：接收阶段触发。
5. 探测阶段发现需要认证时，将该 IP:Port 的认证任务放入认证队列并继续调度。

## 错误处理

- 连接失败或超时：关闭 fd，计数 done。
- I/O 返回 EAGAIN/EWOULDBLOCK：保持状态，等待下一事件。
- 协议响应异常：标记失败，释放资源。
- 认证阶段：仅当所有凭证失败后输出“需要认证但凭证无效”。

## 超时策略

- 每个连接记录 start_ts 与 last_io_ts。
- 使用 EVFILT_TIMER 周期性 tick（例如 100ms）检查超时。
- 超过超时时间的连接直接关闭并计数。

## 资源控制

- 并发 socket 硬上限默认 1000，支持命令行参数覆盖。
- 启动时读取 getrlimit(RLIMIT_NOFILE)，若软限制过低则给出警告；可选自动下调并发上限。
- 任务迭代按需生成，避免过大队列占用内存。

## 测试计划

- 小范围目标验证：
  - 已知可用的 Socks5（无需认证）
  - 需要认证的 Socks5
  - 不可达目标
- 并发测试：在并发=1000 下观察 FD 数、CPU 与稳定性。

## 里程碑

1. 构建 kqueue 事件循环与连接状态机。
2. 接入扫描任务迭代器与并发控制。
3. 替换原有 pthread+select 流程并验证功能一致。
