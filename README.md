# GhostLock (CVE-2026-43499) on Kirin 990 5G / Huawei P40 Pro — 移植进度复盘

> 一个**非持久 root** 的内核提权移植记录：华为 P40 Pro（ELS-AN00，麒麟 990 5G，HarmonyOS 4.2 /
> Android 12，内核 5.10.43）上把 GhostLock 跑到 `uid 0`，以及随后在 SELinux / HKIP 面
> **7 条候选路线全部判死**的完整负结果。
>
> 英文一句话：*A field report of porting GhostLock (CVE-2026-43499) to a Kirin 990 5G device:
> non-persistent uid-0 root achieved from `adb shell` alone, seven SELinux/HKIP bypass candidates
> all falsified — includes the evidence index and the exact reasons each one died.*
>
> 本仓库只放**已脱敏**的复盘与证据索引；原始证据（pstore 转储、反汇编、运行日志）留在私有工作仓库。
> 不含设备 SN / IMEI / 基带 / 账号 / 主机路径。

关键词 / Keywords：GhostLock、CVE-2026-43499、Linux 内核提权、LPE、root、非持久 root、
华为 P40 Pro、ELS-AN00、麒麟 990 5G（Kirin 990 5G）、HarmonyOS 4.2、Android 12、内核 5.10.43、
SELinux、HKIP（Huawei Kernel Integrity Protection）、KASLR、`perf_event_paranoid`、`futex`、
任意读原语 / 任意写原语、adb shell、MRX-W09、GOT-W29。

---

## 1. 一句话结论

**拿到了「重启即失效的 root」**：`uid 0` + 一组 capabilities，但仍在 `u:r:shell:s0` 域里；
从 `adb shell` 起算约 39 秒进入，之后每次提权约 2 秒；重启后一切恢复原状。
**拿不到完整 root**：SELinux 的 MAC 面 7 条候选**全部判死**，所以域换不掉、策略改不了
（`/system` 不可写、SELinux 无法 permissive）。持久 root 因此只剩「解 BL」这一条路。

## 2. 前提条件（都是实测，不是假设）

| 项 | 实测值 |
|---|---|
| 设备 | 华为 P40 Pro，ELS-AN00，麒麟 990 5G |
| 系统 | HarmonyOS 4.2 / Android 12（SDK 31），零售版 |
| 内核 | 5.10.43，构建日 **2025-11-04**（判据只看 `uname -v`，不看 `security_patch` 展示值） |
| BL 状态 | `ro.boot.flash.locked=1`、`verifiedbootstate=green` ⇒ **未解锁**，全程没有短接、没有刷机 |
| 入口 | 只要 `adb shell`（uid 2000 / `u:r:shell:s0`）——不重签 APK、不要 Shizuku、不需要任何 app 配合 |
| 漏洞是否已修 | **没修**：`remove_waiter@0x19d830` 仍用 `current` 取任务指针；内核构建日早于全部 2026 年的 LPE |

## 3. 走过的四步（每步都有可复现判据）

1. **零写泄露**：`perf_event_paranoid = -1`，`perf_event_open` 在 shell 域放行 ⇒ 采样直接拿到
   KASLR slide 与 `current`（task_struct）。这一步不写内核，失败也炸不了设备。
2. **写原语**：`sysctl_perf_event_paranoid` 从 `-1` 改成 `0` 落盘成功。约束很硬——
   只能用「leaf-zero（镜像零页）」当伪锁，且带值写只能装「前 16 字节全 0」的目标，目标必须 8 B 对齐。
3. **任意读**：`random/uuid` 的 `ctl_table`（`.data` 段，镜像偏移 `0x3acb8c0`）当读出口；
   读 A 不改 A，但会把 uuid 指针写到 A+8，这个副作用后面变成了新的判据。
4. **终点**：`task->cred=init_cred` 接线成功（pstore 里能读到 `PID:0`），但 `init_cred.security(+0x78)=NULL`
   ⇒ 第一个 LSM hook 就 oops。最终改成「保持 `u:r:shell:s0` 域 + 只换 cred 的 uid/caps」，终点打通。

写序是硬约束，顺序错了必然 panic：`pre-pid` 写 caps/securebits → 零 pid → **post-pid 只剩 1 次 spray**
→ `setresuid` → `execve`。pid==0 任务一旦 exit 就 `panic("Attempted to kill the idle task")`，
所以「不返回」反而能把窗口拉到 **≥11 分钟**（实测）。

## 4. 判死清单（这部分信息量最大）

| 候选 | 结局 | 死因（关键） |
|---|---|---|
| W1：SELinux permissive | 设计级不可达 | `get_selinux_enforcing` 编译成 `mov w0,#1; ret`，`CONFIG_SECURITY_SELINUX_DEVELOP` 未设 ⇒ `selinux_state` 里根本没有 `enforcing` 成员 |
| `selinux_state+1`（initialized）zero | 判死 | 本镜像 `security_compute_av` 没有「未初始化 ⇒ `allowed=~0`」这一支 |
| `selinux_state+8` 指针清 0 / 指向零页 | 判死 | 它是 Huawei **prmem 保护池**里 8 字节分配，被区间校验；动它两次实测整机进 D 态 |
| `*(state+8)` 的 pointee bit0 清零（第 7 条） | 上机即 **整机 spin** | pointee 恰 8 B、读者只有两处 `ldarb`，理论无 collateral，实测仍死 ⇒ 判死 |
| `cred->security` 换域 | 结构性不可行 | 需要构造合法的 `task_security_struct`，且换完域名要看 LSM 是否复核 |
| HKIP 白名单位图（critdata） | 写被静默丢弃 | 位图本身受保护，写入不落地 |
| `misc` 分区写 BCB 解锁 | 判死 | AOSP BCB，token 词表里**没有** unlock |

方法论教训：**拿到写原语 ≠ 写进去了**。中途有一版 route 报全绿，实际内核一个字节都没改——
从那以后每个证据目录都要求有 pstore / 反汇编这类**外部观测面**。

## 5. 拿到的能力面（以及它的边界）

- **有**：`uid 0`、`CapPrm=CapEff=CapBnd=ffffff8077ac0fff`、`context=u:r:shell:s0`；
  常驻 root worker，`run` 端到端 ≈ 2 s；进程可看、`am/pm/dumpsys` 可用（与 shell 等价）。
- **没有**：caps 只有**低 12 位可控**（位图 = payload 页基址 + 偏移，高 20 位随 KASLR 漂移）
  ⇒ 不能按需补 `SYS_MODULE`/`NET_ADMIN`；跨 uid 的 `kill`、`PTRACE_SEIZE`、`/proc/pid/mem` 全被拒；
  `/data/local/tmp` 建文件仍 EACCES（uid 0 但非 owner + shell 域）。
- **代价**：被顶替的是 pid==0 的 idle 任务，收尾必然 panic 重启 ⇒ 这是「一次会话里干完活」的 root，
  不是日常 root。

## 6. 设备权威数值（便于别人对照，不是通用）

| 符号 / 字段 | 值或偏移 |
|---|---|
| `task_struct` 偏移 | `pid=0x640`、`real_cred=0x7f8`、`cred=0x800`、`comm=0x808` |
| `selinux_state` | `0xffffffc013e13ac8`（`*(state+8)` 运行时 `0xfffffffe87ff0ff8`） |
| `init_cred` | `0xffffffc0134a46a0` |
| 零页（leaf-zero 伪锁） | `image+0x3e00bc8` |
| `random/uuid` ctl_table | `.data`，镜像 delta `0x3acb8c0` |
| `struct rt_mutex_waiter` | 厂商在 `+0x40` 加了 `u32 qos` + `u32 flag`，`prio→0x48`、`deadline→0x50`，无 `ww_ctx` |

> 这些值**只对同一镜像**成立，换版本必重新从固件机器码复算。

## 7. 证据索引

逐目录结论见 [docs/evidence-index.md](docs/evidence-index.md)（33 个证据目录里与本议题相关的 30 个，
每个一句结论 + 关键数字）。

## 8. 现在到哪、下一步

- 路线 C（免解锁提权）**收盘**：机制、写原语、读原语、终点几何全部闭合；MAC 面 7/7 判死，收益封顶。
- 持久 root 只剩 **路线 E：BootROM 内存补丁**（短接进 BootROM 下载态，给运行前的 fastboot 明文打 8 字节补丁，
  再走 `oem unlock`）。离线材料已就绪，只等物理窗口。
- 设备当前状态：出厂零售 4.2.0.121，可正常开机，BL 仍 locked；所有实验都从这个「已知好状态」回滚。

## 9. 相关

- 同一台设备上的刷机 / 救砖工具线（Linux 下的 GUI + CLI + MCP 刷写工具，含这次实验用的 fastboot 引擎）：
  <https://github.com/xiaquwan1001/kirin-tool-linux-refresh>
- 酷安帖（进度分享版）：<https://www.coolapk.com/feed/75225799>

## 10. 免责与边界

- 只在**自己持有的设备**上做，只读取证；不刷 `oeminfo`/`nvme`/`persist`/`modem_secure` 这类不可逆分区；
  每次实验后回滚到可正常开机的零售系统。
- 本文不含可用于其他设备的指纹、密钥或账号信息；偏移数值仅对本文所述镜像成立。
- **不提供成品利用代码**。这里是研究记录，不是教程；照搬到自己设备上变砖自负。
- 文本许可：CC BY 4.0（署名转发即可）。
