# 证据索引（route C / GhostLock 相关）

原始证据（pstore 转储、反汇编、运行日志、二进制）留在私有工作仓库，这里只留**每份证据的结论**，
便于别人对照自己的镜像复核。设备 SN 已打码为 `<SN>`；所有数值只对本文所述镜像成立。

约定：每条 = 「目录 → 一句话结论」。目录名里的日期即实验日期。

## A. 起点与可行性

| 证据目录 | 一句话结论 |
|---|---|
| `2026-11-12-route-c-attack` | 首次真机攻击：native exit code=1（失败），但**路线本身被真机验证**——profile 能被载入并跑到终点前的步骤 |
| `2026-11-14-route-c-anchor` | 四步判定里最关键的一步：**写原语已证**（`perf_event_paranoid` -1→0 落盘，回读与 pstore 双证） |
| `2026-11-14-route-c-secimage` | cred 指针写**确实落地**（pstore `PID:0`），真实阻塞是 `init_cred.security(+0x78)=NULL` ⇒ 第一个 LSM hook oops |
| `2026-11-15-route-c-waiter-order` | 离线修正：厂商在 `rt_mutex_waiter+0x40` 增加 `qos`/`flag`，上游 11 字 strip 的 `prio/deadline/ww_ctx` 布局对本镜像不成立 |

## B. 读原语与 uid 0

| 证据目录 | 一句话结论 |
|---|---|
| `2026-11-15-route-c-simple-root` | **任意读原语成立**（`random/uuid` ctl_table）+ 就地改自身 cred ⇒ `uid 0` 且保留 `u:r:shell:s0` |
| `2026-11-14-route-c-endpoint5` | 终点第 5 步（pointer 写）的树故障实验：用未映射 VA 反推「被走的 waiter 是不是本次 stamp」 |
| `2026-11-14-route-c-ptrprobe` | 落点探针失败 + 方向纠正（写「自报 landed」不代表落在 target） |
| `2026-11-14-route-c-park` | park 已到，但证据通道全被 SELinux 拒；7 次真机 run（含 3 次 panic 自动重启，设备未 brick） |
| `2026-11-14-route-c-capability` | park 后唯一可用的 exfil 通道 = `prctl(PR_SET_NAME)` + `/proc/<pid>/status` 的 `Name:`（15 字节/槽） |
| `2026-11-14-route-c-dump` | 分区转储通了：父进程 `pread` → 64 KB 共享窗 → fork 的 shell 子进程落盘 |
| `2026-11-14-route-c-survey` | root 窗口内 11 个分区内容普查（纯只读，69 MB 原始镜像留私有仓） |

## C. 能力面（caps / securebits / 窗口）

| 证据目录 | 一句话结论 |
|---|---|
| `2026-11-15-route-c-root-shell` | 能执行命令的 `uid 0` shell（exec 顶替 pid=0 任务）；`CapEff=0` 的能力边界 |
| `2026-11-15-route-c-root-worker` | 升级成**常驻 root worker**（0666 文件下发命令），`run` 端到端 ≈ 2 s，不再需要每次 spray |
| `2026-11-15-route-c-window` | 订正：「≈14 s 软复位」不是厂商计时器，而是 pid==0 任务 `do_exit` 触发 `Attempted to kill the idle task` ⇒ **不返回即可延窗**（实测 ≥11 min） |
| `2026-11-15-route-c-caps-attempt` | 负结果：带值写自报 landed，但 `CapEff` 仍 0（后被证为**误判**） |
| `2026-11-15-route-c-caps-ok` | 用落点探针纠正上一次误判，caps 真正写进 `cred`；发现 `execve` 会丢 effective caps |
| `2026-11-15-route-c-caps-exec` | `execve` 攻关：HKIP 判据 + 内核 cap 语义 + `init_cred` 指针写「落地即死」现场 |
| `2026-11-16-caps-exec-securebits` | **真因是 `cred->securebits=47`（`SECURE_NOROOT`）** ⇒ `handle_privileged_root()` 直接 return；这才是 exec 后 caps 全 0 的原因 |
| `2026-11-17-pending-verify` | 能力面 10 项上机（8 闭环）：跨 uid `kill`/ptrace/`/proc/pid/mem` 全拒、caps 只低 12 位可控、HKIP 判在 cred 变更、`am/pm/dumpsys` 与 shell 等价 |

## D. MAC 面判死（7 条候选）

| 证据目录 | 一句话结论 |
|---|---|
| `2026-11-14-route-c-misc` | `misc` 机制定案：AOSP BCB，token 词表**无 unlock** ⇒「写 misc 能解锁」作废（纯离线，28 条判据自检） |
| `2026-11-16-selinux-swap-blocked` | `cred->security` 换域**结构性不可行**：带值写要求被写指针是 walk-safe rb 节点（前 16 B 为 0），而任何真实 `task_security_struct` 前 8 B 是 `{osid,sid}` |
| `2026-11-16-hkip-whitelist` | HKIP 白名单位图 = `critdata`，**我们的内核写被静默丢弃**；且 HKIP 判定点不止一处 |
| `2026-11-16-selinux-zero-discriminator` | `selinux_state` 判别：门槛不在 `initialized`，写也不是被丢弃（推翻了 11-14 的 HKIP 归因） |
| `2026-11-16-static-mac-fastpath` | 静态复核：permit-all 快速分支确实存在 ⇒「MAC 面全判死」需修正，新候选 = `*(state+8)` 的 pointee |
| `2026-11-17-static-state8-pointee` | 静态定查：`*(state+8)` 是华为 prmem 池的 8 B 分配（`selinux_protection_init`），读者仅 2 处 `ldarb`，其余 7 字节无消费者 ⇒ leaf-zero 整字无 collateral |
| `2026-11-17-state8-pointee-write` | 第 7 条候选上机 ⇒ **整机 spin**，理论可行但实测判死（至此 7/7 全死） |

## D2. 生命周期与「更强原语」排查（2026-11-25）

| 证据目录 | 一句话结论 |
|---|---|
| `2026-11-25-detached-root` | root worker 42 s 到 `uid=0`；`adb kill-server` 后存活 35 s+；**物理拔 USB ⇒ worker 被杀 → panic 自动重启**（`bootreason=abnormal`）⇒ root 期间必须保持 USB |
| `2026-11-25-bpf-surface` | 内核「更强写原语」逐个上机排除：**BPF**（`bpf()`/`BPF_PROG_LOAD` 均 EACCES，verifier 未进入）、**Mali kbase**（`/dev/mali0` 0666 可 open，但 `VERSION_CHECK`/`SET_FLAGS` 全 EPERM）、keyring（`add_key` EACCES）、节点可达性 22 项、`/proc/slabinfo` 可读 |

## E. 相邻事实（解锁侧，供对照）

| 证据目录 | 一句话结论 |
|---|---|
| `2026-11-11T1030-fastboot-vendor-stage` | 厂商「Unlock Fastboot」= **假解锁**：搬运链路全通（`12d1:3609`→`18d1:d00d`、`product=kirin990`），但 `oem unlock` 恒回 `already fastboot unlocked`，重启后 `flash.locked=1` |
