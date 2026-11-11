# ghlab

**一个常驻的 Ghidra，透过一个极小的 JSON/HTTP 接口暴露给 agent 和脚本。**

Ghidra 的分析能力很强，但每次 `analyzeHeadless` 冷启动 30–45 秒、无法增量重用结果，agent 交互式逆向基本不可行。
ghlab 把 Ghidra 的 headless JVM 变成**常驻进程**：一次导入、分析落盘，之后每次查询 0.1–2.5 秒，而且天生支持"批量反编译 + 服务端过滤"，非常适合 LLM 上下文有限的场景。

```
agent / shell / 脚本
        │  POST {"cmd": "decompile", "binary": "notepad.exe", "match": "WinMain", "grep": "CreateWindow"}
        ▼
  ghlab daemon (常驻 JVM, 请求串行)  ──→  Ghidra 12.x headless  (pyghidra 3.2 / jpype 1.5)
        ▲                               │
        └── ~/re/proj (Ghidra project, 分析结果已保存，重启不重跑)
```

## 为什么不是现成的 MCP server

| | pyghidra-mcp | GhidraMCP 2.0 | **ghlab** |
|---|---|---|---|
| Ghidra 12.2 | ✅ | 需自行 build（2.0 针对 12.1.4） | ✅ 实测 |
| 安装 | 全套 pip 依赖（chromadb…） | 插件 jar | **零第三方依赖**（stdlib + Ghidra 自带 wheel） |
| 批量反编译 + 服务端 grep | 部分 | ❌ | ✅ 核心能力 |
| 接口 | MCP（pi 默认 codemode 暴露） | MCP + 内置 UI | JSON/HTTP，透明可测 |
| 常驻、多二进制、结果复用 | ✅ | ✅ | ✅ |

ghlab 只做一件事：**把 Ghidra 的分析结果变成 agent 能低成本消费的小块 JSON**。

## 安装（离线可行）

```bash
# 1. 从 Ghidra 安装目录自带的 wheel 建 venv（无需联网）
GHD="C:/ghidra_12.2_PUBLIC"
uv venv --python 3.12 ~/re/.venv
uv pip install --python ~/re/.venv/Scripts/python.exe --no-index \
   --find-links "$GHD/Ghidra/Features/PyGhidra/pypkg/dist" jpype1 pyghidra setuptools wheel

# 2. 安装本项目（editable）
uv pip install --python ~/re/.venv/Scripts/python.exe --no-build-isolation -e .

# 3. 记住这台机器的 Ghidra 与项目位置（写 ~/.ghlab/config.json，之后不必再设环境变量）
ghlab setup --ghidra "$GHD" --project-dir ~/re/proj --project-name ghlab --port 8765

# 4. 启动并自检
ghlab start                          # 后台常驻，日志 ~/re/logs/ghlab.log
ghlab doctor                         # 逐项检查 Ghidra/JDK/pyghidra/wheels/daemon/项目目录
```

`ghlab doctor` 每一项失败都附一句可执行的修法，输出可直接贴进 issue：

```
  ok    GHIDRA_INSTALL_DIR   C:\ghidra_12.2_PUBLIC (setup file)
  ok    ghidra launcher      C:\ghidra_12.2_PUBLIC\support\analyzeHeadless
  ok    java                 C:\Program Files\...\bin\java.EXE
  ok    pyghidra + jpype     jpype=True pyghidra=True (...\python.exe)
  ok    offline wheels       25 wheel(s)
  ok    daemon               http://127.0.0.1:8765/ project=... binaries=4 busy=-
  warn  daemon code          running=3b57affee3fa installed=210d7b59c8bb
  ok    project dir          C:\Users\admin\re\proj
  ok    versions             ghlab 0.1.0 | python 3.12.16 | Windows-11-...
```

Linux/macOS 同理，把 `Scripts/python.exe` 换成 `bin/python`，`export GHIDRA_INSTALL_DIR=/opt/ghidra_12.2_PUBLIC`。

### 跨平台状况（说实话版）

| 部分 | Windows | Linux / macOS |
|---|---|---|
| 分析（session/server/protocol） | 实测 | 代码里没有 Windows API，只用 jpype + Ghidra Java API |
| daemon 生命周期 | 实测（`taskkill`、`netstat`、shim 父进程） | `start_new_session=True` spawn、`os.kill` 停止、`lsof`/`ss` 找端口占用者；**未在真机验证** |
| 出图（`--format svg/dot/mermaid`） | 实测 | 纯 Python 字符串拼接 + `xml.sax.saxutils`，与平台无关 |
| 路径 | 实测（`C:\...`、venv shim） | 全部走 `pathlib`；`~/.ghlab/focus`、`<project>/.ghlab/*` 用 home 相对路径 |
| 安装 | 实测（Ghidra 自带 wheel 离线装） | 同样吃 Ghidra 发行包里的 `pypkg/dist`（含该平台 jpype1 wheel）；若目录里没有对应平台 wheel，就只能 `uv pip install pyghidra`（需联网） |

已知未覆盖：Windows 专属的“venv shim 父进程”处理在 POSIX 上是空转；`ghlab stop` 在 POSIX 靠 `lsof`/`ss` 找残留监听进程，两个都没装时只能靠 pidfile 的 pid。

## 用法

```bash
ghlab import C:/Windows/System32/notepad.exe   # 导入 + 全量分析（约 75s，仅一次）
ghlab import big.exe --no-analyze              # 只导入：字符串/导入立刻可查，分析稍后补
ghlab import fw.bin --show-loaders             # 这个文件能被哪些 loader/语言组合导入
ghlab import fw.bin --language x86:LE:32:default --base 0x8000000   # 固件：指语言 + 指基址
ghlab analyze big.exe --addr 0x1400114c4       # 只分析这一段（2.3s），不是整个程序
ghlab binaries
ghlab info notepad.exe

ghlab functions notepad.exe -m 'WinMain|WndProc'
ghlab decompile notepad.exe -t entry           # 单个，完整源码
ghlab decompile notepad.exe -t FUN_140001008 --max-lines 30

# 批量：把每个 FUN_* 都反编译，只回传命中的行（省 context 的关键）
ghlab decompile notepad.exe -m 'FUN_' -g 'CreateWindow|RegisterClass|GetDlgItem' -n 40

ghlab strings notepad.exe -q txt
ghlab strings notepad.exe -q 'Software\Microsoft' --refs   # 谁用了这个字符串
ghlab imports notepad.exe -m '^Reg'                        # 每个导入有几个调用者、属于哪个风险组
ghlab imports notepad.exe --group registry -n 10           # 只看注册表相关

# 先看全局，再决定花 token 看哪里
ghlab overview                                    # 整个项目一行一个程序
ghlab journal --binary notepad.exe                # 我改过什么（跨会话续接）
ghlab audit                                       # 全项目复算所有断言，列出不成立的
ghlab digest notepad.exe

# 按结构缩小候选集：谁既写注册表又碰 Notepad 字符串
ghlab find notepad.exe -i RegSetValue -s Notepad
ghlab find notepad.exe -i 'VirtualAlloc|VirtualProtect' --any -n 10

ghlab xrefs notepad.exe entry
ghlab graph notepad.exe entry -d 2                # 调用树
ghlab graph notepad.exe entry --direction called   # 调用者树

# 出图：dot / mermaid / svg（svg 自带布局，不需要 graphviz）
ghlab graph notepad.exe entry -d 3 --format svg --out ~/re/graphs/entry.svg
ghlab graph notepad.exe FUN_140021ba8 -d 2 --format mermaid   # 直接贴进 markdown
ghlab graph notepad.exe entry -d 3 --format dot > entry.dot    # 想用 graphviz 再渲染

# 让函数跑一遍（P-code 模拟，不落盘）：给定参数，看它返回什么、写了哪块内存
ghlab emulate notepad.exe __security_check_cookie --arg 1
ghlab emulate notepad.exe FUN_140007e1c --arg 1 --arg '"hello"' --buffer 64
ghlab emulate notepad.exe decrypt_config --arg 0x140038600 --buffer 256 --ms 8000
ghlab emulate notepad.exe check_license --seed '0x140039600=41424344' --dump '0x140039600:8'
# stub a getter so the function can run without the object it reads:
ghlab emulate notepad.exe line_height --arg 0   --stub 'FUN_1800058c0[arg2=0xe000000b]=120' --stub 'FUN_1800058c0[arg2=0xe000001b]=2'

# 密文不知道算法：把常见廉价算法全试一遍，只留"像字符串"的候选
ghlab decrypt --hex '322e2e2a6075753f2c3336743f223b372a363f74393537753b2a33752c6b'
#   [xor 0x5a] printable 1.0 score 0.933
#     http://evil.example.com/api/v1
ghlab decrypt notepad.exe --addr 0x140039600 --len 64      # 直接从程序内存里取

# 两个版本比功能差异（字符串/导入/常量/CFG 形状匹配，不靠地址对齐）
ghlab import C:/samples/app_v1.exe && ghlab import C:/samples/app_v2.exe
ghlab diff app_v1.exe app_v2.exe
ghlab diff app_v1.exe app_v2.exe -m 'decrypt|auth' -n 10
ghlab diff app_v1.exe app_v2.exe --detail 2      # 再加一层：改动函数的指令级 unified diff
ghlab diff app_v1.exe app_v2.exe --semantic       # 再换一个角度：这个程序"多了什么能力"
ghlab bytes notepad.exe 0x1400019d0 --size 32
ghlab rename notepad.exe FUN_140001008 sub_parse_cmdline
ghlab comment notepad.exe 0x1400019d0 'entry stub -> 0x140001850'

# 写：改签名/改数据/打补丁（都落盘，有 --expect 防误写）
ghlab set-type notepad.exe FUN_14001109c 'int sub_parse(char *s, unsigned n)'
ghlab set-type notepad.exe 0x140038600 'char[16]'
ghlab patch notepad.exe 0x1400019d0 --nop 2 --expect 4883        # 只在这两个字节确实是 4883 时才写

# 结论与证据：写进 Ghidra 书签 + 磁盘上的 JSON，最后出 markdown
ghlab bookmark notepad.exe --target __security_check_cookie --category security --text 'cookie 校验在此'
ghlab note notepad.exe 'entry 只做 CRT 初始化' --at entry --tag bootstrap
ghlab notes notepad.exe --tag bootstrap
ghlab report notepad.exe > notepad.md

# 结论带「可复算的断言」：写的时候验证一次，之后随时重算
ghlab note notepad.exe '持久化写入点' --at FUN_14001e02c --tag persistence \
  -a 'string=Software.Microsoft' -a 'import=RegCreateKeyW' -a 'size>=200'
# note #31 [persistence] 14001e02c FUN_14001e02c
#   [OK] string=Software.Microsoft - strings: Software\Microsoft\Notepad
#   [OK] import=RegCreateKeyW - imports: RegCreateKeyW
#   [OK] size>=200 - 213 bytes
ghlab verify notepad.exe            # 全部重算：PASS / FAIL / UNKNOWN

# 批量：一个调用扫完一组函数，只回命中行（不再"每个函数一次往返"）
ghlab map notepad.exe --from 'import:RegSetValueExW' --op decompile -g 'Reg|Autosave'
# import:RegSetValueExW -> decompile (grep: Reg|Autosave), 4/4 function(s), 15 hit(s), 2610ms
#   140021ba8 FUN_140021ba8 (1082b) 9 hit(s)
#       53: LVar6 = RegCreateKeyExW((HKEY)0xffffffff80000001,L"Software\Microsoft\Notepad\Autosave",0,
ghlab map notepad.exe --from 'name:^FUN_14000' --op imports -g Reg -n 50   # 只要导入，不反编译

# 外部知识一次搬进来：头文件/PDB 导出的签名表，一个事务一次落盘，单条失败不影响其它
cat > ~/re/maps/notepad.txt <<'MAP'
FUN_14001e194 = int reg_set_dword(HKEY h, LPCWSTR name, int value)
0x1400390a0 = char[8]
MAP
ghlab types notepad.exe --from ~/re/maps/notepad.txt --dry-run   # 先看计划
ghlab types notepad.exe --from ~/re/maps/notepad.txt

# 有 PDB 就不用猜：符号和类型一次进来（不匹配会被拒绝，函数数不变）
ghlab pdb sample.exe --file ~/re/samples/sample.pdb
# applied ...: functions 1204 -> 1310 (project.save(program))
# 1 applied / 1 failed from ~/re/maps/notepad.txt (project.save(program))
#   OK  14001e194 -> int reg_set_dword(HKEY h, LPCWSTR name, int value)
#   ERR 0x1400390a0: Could not create Data at address 1400390a0

# 跨程序：哪个样本也连这个域名？这个 API 是由哪条路径走到的？这段逻辑在别的样本里叫什么？
ghlab cross-xref 'autosave'                       # 全项目搜字符串，附"谁在用"
ghlab slice notepad.exe RegSetValueExW            # 从入口到该导入的最短调用链
ghlab slice notepad.exe FUN_14001e02c --forward   # 反过来：它能碰到哪些导入、走哪条路
ghlab family notepad.exe                          # 这一族每个样本的规模/枢纽/已有结论
ghlab similar notepad.exe FUN_140021ba8 --against other.exe
```

任何命令加 `--json` 得到原始结构；`GHLAB_URL=http://host:port` 可指向远端 daemon。
不带参数直接 `POST` 也行（`Content-Type` 必须是 `application/json`，否则 415 —— `text/plain` 的跨站请求不触发 CORS 预检，放开它等于让任意网页驱动 `patch`）：

```bash
curl -s localhost:8765/ -H 'Content-Type: application/json' \
  -d '{"cmd":"decompile","binary":"notepad.exe","targets":["entry"],"include_callees":true}'
curl -s localhost:8765/ | jq          # 自描述的命令表
```

请求体必须带 `Content-Length`（chunked 回 411），上限 8 MiB、30s 内发完（超时 408）；`HEAD /` 与 `GET /` 同头无体，`curl -I` 能直接看到 daemon 是否活着。

## 可重放脚本（`ghlab run`）

分析一个样本往往要十几条命令。把顺序写成脚本，下次换个样本只改一个变量：

```
# ~/re/pipes/triage.gh
digest $BIN --top 4
find $BIN -i RegSetValueExW
slice $BIN RegSetValueExW -n 2
report $BIN --top 3 > ~/re/pipes/$BIN.md
```

```bash
ghlab run ~/re/pipes/triage.gh --set BIN=notepad.exe
# [1/4] digest: ok (79ms)
# [2/4] find: ok (31ms)
# [3/4] slice: ok (62ms)
# [4/4] report: ok (63ms)
# 4/4 steps ok in 266ms
```

规则只有四条：一行一条命令、`#` 注释、`$VAR` 来自 `--set`、`>`/`>>` 把这一步的 stdout 写进文件。
`--keep-going` 失败继续，`--dry-run` 只解析不执行。中转义只在引号前生效（所以 `C:\tmp\a.md` 不会被吃掉反斜杠）。

## 家族聚类（`ghlab campaign`）

```bash
$ ghlab campaign
3 program(s) -> 1 cluster(s) at min_score 0.35
  [1] 3 member(s), max 1.00
      notepad.exe, notepad_p2.exe, notepad_patched.exe
      imports: AbortDoc, AcquireSRWLockExclusive, AcquireSRWLockShared, ...
      strings: \Microsoft\WindowsApps\Microsoft.WindowsNotepad_8wekyb3d8bbwe
otepad.exe, ...
```

单位是**整个程序**（所有函数指纹的并集），不是单个函数：同一工具的不同构建会并成一簇，无关样本各自独立。
用单链（single linkage）是故意的——中间夹一个 loader stub 也应该把两个样本拉到一起。
`--min-score` 调松紧，短于 4 字符的字符串（`%s`、填充）不参与展示。

## 多项目路由（一份 MCP 配置，多个 Ghidra 库）

一台机器常有好几个库（notepad 的玩具库、WPS 的反汇编库……）。以前要复制多份 MCP 条目、
各配一个 URL；现在一个条目就够，`ghlab` 按工具参数里的 `binary` 决定转发给哪个 daemon：

```bash
ghlab setup --discover                        # 扫描 ~/re，把已有的 Ghidra 项目都认出来
ghlab setup --discover ~/work/binaries --dry-run   # 只看不注册
ghlab setup --add-project wps --add-port 8766 \      # 手工指定也行
    --project-dir ~/re/wps/proj --project-name wps
ghlab setup --default-project ghlab           # 不带 binary 的命令打到哪个库
ghlab projects                                # 每个库的状态 + 里面有什么
```

`--discover` 只认 Ghidra 真正能打开的形态：同一目录下同时有 `<name>.gpr` 与 `<name>.rep/`
（GUI 建的、`analyzeHeadless` 建的、本工具建的都一样）。已经注册过的目录或名字会跳过，
新项目自动分配一个既不在注册表里、也没人监听的端口；`--dry-run` 只列不改。**不会重新分析**——
项目里已有的函数、注释、类型直接可用（实测：`analyzeHeadless` 建的库里 `info` 立刻报 855 个函数）。

```
# 2 project(s), default = ghlab
  project    state  binaries  url / dir
  wps        up        1  http://127.0.0.1:8766  (C:/Users/admin/re/wps/proj)
      wpscore.dll
 *ghlab      up        4  http://127.0.0.1:8765  (C:/Users/admin/re/proj)
      notepad.exe
```

规则（`src/ghlab/router.py` + `config.discover_projects`，24 个单测覆盖，全部不需要 socket）：

1. `project=<名字>` 显式指定，优先级最高（参数不会转给 daemon）。
2. 有 `binary`（或 `diff` 的 `a`/`b`）：问每个 daemon 有哪些程序，转发给**拥有它的那个**；
   `-` 表示焦点程序，同样先解析归属。查不到时报错会列出每个库都有什么。
3. 两个 daemon 都有同名程序：报错要求加 `project=`，不猜。
4. `diff` 的两个程序必须同库，否则直接告诉你要先导进一个库。
5. 没有任何 `binary` 的命令（`journal`/`audit`/`import`…）走默认库；`binaries` 与
   `overview` **跨库聚合**，每行带 `project` 字段——"我手头有什么"本来就该一次问完。
6. 目标库的 daemon 没起且开了 `GHLAB_AUTOSTART=1`：先把它启动（服务名会说清是哪个库），再重试一次；启动失败只试一次，不循环。

MCP 侧多了一个 `ghlab_projects` 工具（22 个），agent 可以先看"哪个库有这个文件"再动手。

## 接 MCP（给别的 agent 用）

```bash
ghlab mcp          # stdio MCP server，转调本机 daemon
```

只暴露 22 个"问问题"的工具，而不是把 200 个 Ghidra 动作一一映射：

| 工具 | 干什么 |
|---|---|
| `ghlab_digest` | 一次性 triage（先调这个） |
| `ghlab_find` | 按导入/字符串/调用者定位候选 |
| `ghlab_decompile` | 单函数 / 正则批量 / 服务端 grep（走缓存） |
| `ghlab_diff` | 两个程序的功能级差异 |
| `ghlab_slice` | 从导入回溯到 entry 的调用链 |
| `ghlab_emulate` | P-code 模拟执行，取返回值与内存写入 |
| `ghlab_cross_xref` | 全项目搜字符串，附引用者 |
| `ghlab_similar` | 跨样本同构函数 |
| `ghlab_note` / `ghlab_verify` / `ghlab_report` | 记结论（带断言） / 重算断言 / 出报告 |
| `ghlab_notes` / `ghlab_audit` / `ghlab_overview` | 读回历史结论 / 全项目复算断言 / 项目总览 |
| `ghlab_decrypt` | 破小块密文（xor/add/rot/utf16/base64） |
| `ghlab_map` / `ghlab_types` / `ghlab_pdb` | 批量扫函数 / 批量写类型 / 吃 PDB 符号 |
| `ghlab_projects` | 有哪些库、哪些 daemon 在线、每个库装了什么（多项目路由的入口） |

还有资源：`ghlab://programs`（名字 + md5 + 架构 + 函数数）、`ghlab://program/<name>/digest`、`ghlab://program/<name>/notes`。

以及两个 **prompt 模板**，把"该怎么问"也一起给出去，客户端不用读文档就能起步：

| prompt | 行为 |
|---|---|
| `triage(binary)` | 先把 `digest` 结果**渲染好人读格式**内联进去（实测 613 token），再附固定顺序的下一步：`find` → `slice` → `decompile`（先 grep）→ `note` → `report` |
| `diff-review(a, b)` | 先把 `diff` 摘要内联（205 token），再要求逐函数判断"功能变化 vs 噪声（地址/常量/内联）"，怀疑是修复时点出漏洞类别 |

prompt 里内联的是 CLI 的人读格式而不是 JSON——同一份 digest，JSON 美化后 5935 字符，人读格式 2453 字符。
MCP 进程本身不起 JVM，客户端可以随时重启它；daemon 用 `ghlab start` 管着就行。

pi 里注册（`ghlab setup --print-mcp` 会按本机真实路径打印可直接粘贴的版本；`exposure: deferred` 表示用 tool_search 按需加载）：

```json
{"mcpServers": {"ghlab": {"command": "C:\Users\admin\re\.venv\Scripts\python.exe",
  "args": ["-m", "ghlab.mcp"],
  "env": {"GHLAB_URL": "http://127.0.0.1:8765", "GHLAB_TIMEOUT": "900",
          "GHLAB_AUTOSTART": "1", "GHLAB_PROJECT_DIR": "C:/Users/admin/re/proj",
          "GHLAB_PROJECT_NAME": "ghlab", "GHLAB_PORT": "8765"},
  "exposure": "deferred"}}}
```

- **`GHLAB_AUTOSTART=1`**：daemon 没起时首次工具调用自己把它拉起来（冷启 30–45s，之后毫秒级），agent 不需要先开 shell。
- **一个 MCP 条目 = 一个 daemon**：换项目就再写一个条目（不同 `GHLAB_PORT` / `GHLAB_PROJECT_DIR`）。
- 其他 MCP 客户端（Claude Code 等）用同一个块，删掉 `exposure` 即可；`ghlab doctor` 负责回答"这台机器为什么跑不起来"。

## 命令一览

| cmd | 参数（必填 / 可选） | 说明 |
|---|---|---|
| `ping` | – | 存活 + 项目信息 |
| `binaries` | – | 项目内程序 |
| `import` | `path` / `analyze, base, language, cspec, name, overwrite, show_loaders` | 导入并分析。`--base 0x8000000` 换加载基址（在首次保存前重定位，分析后搬就等于让代码指向旧地址）；`--language x86:LE:32:default --cspec gcc` 强指定语言（固件/blob 靠它，`--show-loaders FILE` 先列出 Ghidra 认得的组合）；`--name` 换项目里的名字，`--overwrite` 替换已存在的同名程序 |
| `analyze` | `binary` / `addr, full` | **增量分析**：`--addr` 只反汇编 + 建函数这一处（实测 2.3s，函数总数不变）；`--full` 重跑全量（notepad 实测 163s，比首次导入还慢——全量分析别当常用操作） |
| `info` | `binary` | 语言、基址、MD5、函数数、段 |
| `functions` | `binary` / `match, limit, offset` | 按名过滤列函数 |
| `decompile` | `binary` / `targets, target, match, grep, limit, max_lines, include_code, include_callees, include_callers, timeout, refresh` | 单个 / 批量 / 服务端 grep；结果按 `md5+地址+签名+注释` 缓存到 `<项目>/.ghlab/cache/<md5>/`，热查询 2.5s → 0.19s；`patch`/`set-type`/`types`/`pdb`/`analyze` 保存后自动清空该程序的缓存，`--refresh` 仍可手动强制重算 |
| `strings` | `binary` / `query, limit, offset, refs` | 字符串数据搜索；`--refs` 顺带给出引用它的函数（含大小），并在头部汇总“哪个函数用的字符串最多”（实测 0.28s / 4 条） |
| `xrefs` | `binary` / `target, targets` | 引用（谁引用了它） |
| `imports` | `binary` / `match, query, group, limit` | **导入下钻**：每个导入的 distinct 调用者数 + 最大的 3 个调用者 + 风险组（`digest` 只给计数，这个给名字）。`--group` 取值 anti/crypto/exec/file/inject/network/registry/ui，写错会报错并列出合法值 |
| `exports` | `binary` / `match, query, limit` | **导出面**：这个二进制对外开放的入口（PE 导出表 / ELF `.dynsym`），每个都附还原后的 C++ 名字（`_Z`/`?` 开头的走 Ghidra 自带 demangler）。`imports` 问"我调用了谁"，这个问"别人能调用我什么"——拿到 DLL/SO 先看它，能直接看出 SDK 边界与插件入口 |
| `bytes` | `binary, addr` / `size` | 原始字节 hex+ascii。一次 `getBytes` 读完（不是逐字节），按“包含首地址的已初始化块”截断，上限 64 KiB；读短了或超上限返回 `size` 与 `truncated: true` |
| `scan` | `binary, offset`（或 `hex`）/ `range, func, limit, op, stack, imm, writes, sequence, window` | **位移搜索**：谁在读写结构体的 `+0xNN` 字段（指令级，不是反编译文本 grep）。`--op` 过滤助记符（如只看 `MOVSS`/`MULSS` 找 float 字段），`--func`/`--range` 限定范围，默认排除 `[RSP/RBP±]` 栈局部变量（`--stack` 放回）；`--writes` 只看写入（偏移在目的操作数），`--imm 4` / `--imm 0..5` 只看立即数匹配的指令（回答"谁把常量 4 存进 +0x44"）。给 `--hex` 则改成**掩码字节搜索**（`48 8B ?? 05`），返回命中地址 + 所在段 + 所属函数。实测 650 万条指令 38s |
| `offsets` | `binary` `target` | `offset` `limit` | 把函数里每个 `[base+disp]` 归属到具体形参/局部变量 |
| `struct` | `binary, target` / `base, offset, name, types, pointer, create, limit` | **结构体推断**：把一个函数里同一 base 的字段访问按访问宽度投票成类型，缺口用 padding 补齐（偏移必须与代码一致），输出可直接编译的 C decl；`--types 0x18=float,0x20=void *` 人工纠正宽度，`--pointer 0x20` 标指针，`--create` 直接装进程序（之后 `set-type` 就能引用）；`offsets` 看归属，这个看布局 |
| `rename` | `binary, target, new` | 重命名并保存 |
| `comment` | `binary, target, text` / `type` | 写注释并保存（type: plate/pre/post/eol，默认 plate；`decompiler` → pre） |
| `graph` | `binary, target` / `direction, depth, limit, format, out` | 调用树 BFS；`--format dot/mermaid/svg` 出图，`--out` 落盘（svg 是自绘的，无需 graphviz；dot 想再加工就交给 graphviz） |
| `overview` | – | **项目总览**：每个程序的函数数/字符串数/导入数/结论数/失败断言数 + 最后一次改动（走索引，实测 3 个程序 2.7s） |
| `journal` | – / `binary, op, since, limit` | **变更日志**（`.ghlab/journal.jsonl`）：所有写操作自动记录（import/analyze/rename/comment/patch/set_type/types/pdb/note/bookmark），失败也记 |
| `audit` | – / `binary` | **全项目复算**：把所有结论里的断言重算一遍，列出 FAIL/UNKNOWN |
| `digest` | `binary` / `top, strings` | **一次性 triage**：入口链、按风险分组的导入、API 组合、字符串分类、调用图枢纽、函数大小分布（实测 notepad ≈450 token / 2.7s） |
| `index` | `binary` / `refresh` | **持久索引**：一次全扫把每个函数的 strings/imports/callees/常量/大小写进 `<project>/.ghlab/index/<binary>.json`；`find`/`diff`/`similar`/`campaign` 都改读索引，`(md5, modification number)` 变了就自动重建 |
| `find` | `binary` / `import, string, calls, limit, any` | **按结构定位候选**：谁调用了这些导入 / 引用了这些字符串 / 调用了这些函数（默认全部条件同时成立，`--any` 取或） |
| `decrypt` | – / `binary, addr, len, hex, ciphers, min_printable, limit` | **破小块密文**：单字节 xor/add/sub、rol/ror、utf-16le、base64 全试一遍，只留"像字符串"的候选（要求至少一段 4 字母连写），按可打印度 + 字母数字占比 + 配置关键词打分排序。`--hex` 直接给密文，或给 `binary`+`--addr/--len` 从内存读 |
| `emulate` | `binary, target` / `args, max_insns, ms, buffer, dump, seed, stub` | **P-code 模拟执行**：按 Win64 约定播种参数（`123`/`0x40`/`"str"`/`L"wide"`/`*symbol`），自动应答 memset/memcpy/strlen/strcpy 等 CRT 调用，未实现的导入返回 0，回传返回值、可写内存 diff、`--buffer` 内容、停止原因；`--seed ADDR=HEX` 可预置内存（喂密文/配置），`--stub FN[ARGn=V]=RET` 可跳过某个调用并直接给返回值（按第 1–4 个整数参数匹配），用于"函数读配置再计算"的场景 |
| `diff` | `a, b` / `match, limit, min_score, detail, semantic` | **功能级差异**：每个函数提取（引用的字符串、外部导入、常量、指令/块/调用数），四轮匹配（签名唯一 → 同地址 → 同名 → 相似度贪心），输出 added/removed/changed + 段 hash 差异（实测 521 函数两边共 2–4s，命中缓存的重复查询 <0.1s）；`--detail N` 再给 N 个改动函数出指令级 unified diff（地址归一化成 `ADDR`）；`--semantic` 换成整库视角：新增/移除的**导入（带 inject/exec/network… 风险分组）、字符串、常量**，`counts` 永远是真实总数（列表按 `-n` 截断并标 `truncated`） |
| `patch` | `binary, addr` / `bytes, nop, expect` | **真打补丁**：先 `clearCodeUnits` 再写（否则 Ghidra 报 `Memory change conflicts with instruction`），随后重新反汇编并落盘；只读段会临时置写。`--expect` 长度必须与写入等长 || `patch` | `binary, addr` / `bytes, nop, expect` | **真打补丁**：先 `clearCodeUnits` 再写（否则 Ghidra 报 `Memory change conflicts with instruction`），随后重新反汇编并落盘；只读段会临时置写。`--expect` 长度必须与写入等长 |
| `revert` | `binary` / `addr, all, force` | **撤销补丁**：`patch` 会把被覆盖的原字节记到 `<项目>/.ghlab/patches/`，`revert BIN 0x401000` 还原那一处，`--all` 按从新到旧把整个补丁栈退回去（同一地址打了两次就退两次）。若当前字节已不是当初写入的（说明后来又被改过），默认拒绝并报出两边内容，`--force` 才强行覆盖——默认拒绝是刻意的：那已经是另一处编辑，不是 undo |
| `set_type` | `binary, target, decl` | **写类型**：`'int f(char *s, unsigned n)'` 走 `FunctionSignatureParser`（名字以声明为准），`'char[64]'`/`'void*'`/`'DWORD'` 走 `CreateDataCmd` |
| `bookmark` | `binary` / `action, addr, target, type, category, comment, limit` | Ghidra 书签 add/list/remove（GUI 里能直接看到，类别当分组用） |
| `note` | `binary, text` / `at, addr, tag, assert, delete` | 追加一条结论：写 `<项目>/.ghlab/notes/<binary>.json` + 同名书签；`-a const=0x41` / `string=` / `import=` / `calls=` / `size>=` / `bytes=` / `symbol=` / `name=` 附**可复算断言**（写入时就验一次） |
| `map` | `binary` / `from, op, grep, limit, hits` | **批量原语**：`--from` 选函数集（`all`/`name:`/`import:`/`calls:`/`string:`/`const:`/`addr:`），`--op` 取 `decompile`/`strings`/`imports`/`calls`/`consts`，`-g` 只留命中行。4 个函数反编译+过滤 ≈2.6s，回 15 行而不是 4 份源码 |
| `pdb` | `binary, file` / `untrusted` | **吃调试符号**：`PdbUniversalAnalyzer.doAnalysis` 套壳；PDB 与二进制不匹配时不写入（`functions_before == functions_after`），日志一并返回 |
| `types` | `binary, from` / `dry_run` | **批量写类型**：签名表（`.json` 分组或 `target = decl` 文本）一次应用，一个事务一次 `save`；`--dry-run` 只列计划；单条失败进 `failed` 不中断 |
| `verify` | `binary` / `id` | **重算所有断言**：`PASS`/`FAIL`/`UNKNOWN` + 每条证据行；发现 agent 说错了就靠这个 |
| `notes` | `binary` / `tag, at, query, limit` | 按标签/位置/关键词检索结论 |
| `cross-xref` | `query` / `binary, limit` | **跨程序**搜字符串数据，附每个命中的引用者；省掉"逐个程序 decompile 找字符串" |
| `slice` | `binary, to` / `from, depth, limit, code, direction` | **反向切片**：沿调用者 BFS 到 entry/main/WinMain/DllMain，给出"什么条件下这个 API 会被调用"的链；`--code` 附调用者反编译；`--forward` 反向问"这个函数能到达哪些导入、路径是什么" |
| `similar` | `binary, target` / `against, limit, min_score` | **跨程序同构函数**：字符串/导入/常量/大小四路指纹打分；零特征的 thunk 一律压到 0.3 以下，避免 stub 互相当成 1.00 |
| `report` | `binary` / `top` | Markdown 报告：digest 摘要 + 调用图枢纽 + 函数大小分布 + 按标签分组的结论，可直接贴进报告 |

| `run` | `path` / `set, keep_going, dry_run` | 执行 `.gh` 脚本（`$VAR`、`>` 重定向、失败策略） |
| `mcp` | – | 以 stdio MCP server 形式暴露 32 个工具 + `ghlab://` 资源 + 2 个 prompt 模板 |
| `campaign` | – / `binary, min_score, limit` | **家族聚类**：把项目里所有程序按"共享导入 0.6 + 共享字符串 0.4"的相似度做单链聚类，输出每簇成员与共有特征（3 个 notepad 变体 → 1 簇 max 1.00，约 5s） |
| `family` | – / `binary, min_score, limit` | **家族报告**：对 `campaign` 分出的某一族，逐样本给出函数数/字符串数/导入数/调用枢纽/已有结论数与标签，外加全族共有导入与共有字符串（长串优先，单行截断） |

`target` 可以是符号名或 `0x` 地址；`binary` 支持唯一子串匹配。
写操作（rename/comment）放在 Ghidra transaction 里并立即 `program.save()`。

```bash
# 结构体偏移 → 消费点：找出所有读写 PapProp.LineSpacing(+0x54) 的指令
ghlab scan wpscore.dll 0x54 --op '^(MOVSS|MULSS|DIVSS|ADDSS|COMISS)' -n 60
# 只看某个函数内部，且把栈变量也放进来
ghlab scan sample.exe 0x18 --func decrypt_string --stack
# 谁把常量 4 写进结构体的 +0x44？（反编译里看不到立即数写点时用它）
ghlab scan sample.exe 0x44 --writes --imm 4
```

## 设计要点

- **常驻 + 项目落盘**：`~/re/proj/ghlab` 是普通 Ghidra 项目，Ghidra GUI 也能打开看，两边结果一致。
- **串行 Ghidra 调用**：Ghidra 的 transaction 不是线程安全的，所有命令经一把 `LOCK` 串行；HTTP 层仍是多线程，所以长任务跑着的时候 `GET /`（busy、命令表）照常响应。
- **服务端过滤**：`grep` 在 daemon 侧执行，只回传 `{line, text}`，几百个函数的扫描也只占几百 token。
- **零依赖**：`protocol.py`/`client.py` 只用 stdlib，`session.py` 才懒加载 pyghidra → 单元测试和 CLI 都能在没有 Ghidra 的机器上跑。
- **协议自描述**：`GET /` 返回全部命令及其参数，agent 可自举。
- **模拟执行是"够用主义"**：`EmulatorHelper` 在独立内存里跑，写入不落回 program；外部导入用 Python 应答（CRT 真的有语义，其余返回 0），`lock` 等未实现的 p-code op 直接跳过并在输出里点名。所以它适合解密循环、配置解析、返回值推演，不适合依赖真实 API 语义的逻辑。
- **diff 不假设地址对齐**：指纹是"这个函数引用了哪些字符串/调用了哪些导入/用了哪些常量/多大/多少块"，匹配时先找签名唯一的，再退同地址（同基址补丁）、同名（有符号）、最后相似度贪心（阈值 `--min-score`）。所以既能比同源补丁，也能比隔了几个版本的构建。
- **缓存键里不放指令字节**：第一次反编译会重写 code unit，反编译前算的哈希和之后算的永远不等，所以键用 `md5+地址+函数签名+注释`。补丁改了字节而键不变，所以缓存按 `<md5>/` 分目录，写操作保存成功后整目录删掉——不用记着 `--refresh`。
- **打开的 program 有上限**：每个打开的 program 都会把符号表、反编译器和地址索引留在堆里，摸过十个二进制就占十份。`GHLAB_MAX_OPEN_PROGRAMS`（默认 4）按最近使用淘汰，被淘汰的 program 会被 `release`（下次用到重新打开，项目本身没变）。
- **能看不能改**：`GHLAB_READONLY=1` 起的 daemon 会拒绝所有写命令
  （`patch`/`set_type`/`types`/`pdb`/`rename`/`comment`/`note`/`bookmark`/`import`/`analyze`），
  返回 `PermissionError` 且 handler 根本不执行；`audit`/`verify` 照常跑，只是不写回 notes 文件。
  `ping` 与 `GET /` 会带上 `readonly: true`，客户端能自己判断。

  ```bash
  GHLAB_READONLY=1 ghlab serve --port 8765   # 交给模型/同事的脚本时用
  ```
- **相似度必须防 stub 噪声**：几百个 29 字节 thunk 的空指纹两两相似度都是 1.00，所以"没有任何共享字符串/导入/常量"的候选一律压到 0.3 以下。
- **写操作全部落盘、全部可校验**：`patch` 要求 `--expect` 长度与写入一致（防手滑写错位置），改完重新反汇编；`set_type` 以声明里的名字为准；`note` 同时写 Ghidra 书签和磁盘 JSON——书签给 GUI 用户看，JSON 给 agent 和 `report` 用，两边不互相依赖（Ghidra 崩了结论还在）。
- **图要不依赖外部工具也能看**：SVG 自己按 BFS 层次排（列=深度，行=同层节点），不装 graphviz 也能直接丢浏览器/报告；DOT/Mermaid 是给“还要再加工”的场景留的接口
- **下钻要顺着“谁用了它”走**：`strings --refs` 和 `imports` 把“字符串/API → 函数”这一步做成一次调用。agent 最常做的动作是“找到用它的函数”，而不是“列出所有字符串”
- **批量是原语，不是循环**：agent 最贵的资源是往返次数和上下文，所以 `map` 在服务端选函数、反编译（走缓存）、过滤，只回命中行。"每个候选函数跑一次"这种活不要交给 shell 循环。
- **差异要分两层看**：`diff` 回答"哪个函数变了"，`--semantic` 回答"多了什么本事"——后者不看函数边界，只看整个二进制的导入/字符串/常量集合，所以能回答"这版是不是加了联网/加了新的命令行参数"，而不必逐个函数读。注意它比的是**值**不是地址（字符串按内容、常量按数值）。
- **差异要落到指令上**：`diff` 先按指纹回答"哪个函数变了"，`--detail N` 再回答"变成了什么"——指令级 unified diff，绝对地址归一化成 `ADDR`，所以插入/删除指令也能对齐。
- **位移搜索比类型更早可用**：没有类型信息时，"谁碰了 +0x54" 只能靠扫描指令里的 disp 得到（反编译文本里 float 字段常常被放进 XMM 参数，grep 不到）
- **索引比命令更值钱**：每次调用都全扫是 agent 用不起的。`index` 把每个函数的事实（字符串、导入、被调函数、常量、大小、指令数、基本块数）落成一份 JSON，`find` 从 2.5s 降到 0.16s、`diff` 从 4.4s 降到 0.8s，`similar`/`campaign` 一并变快。失效判定是 `(md5, modification number)`：任何通过 ghlab 的写操作都会让它加一，旧索引不可能被当成新的；`note` 只写 JSON + 书签，不动程序事实，索引仍然有效。
- **日志比记忆可靠**：所有写操作落 `.ghlab/journal.jsonl`，`overview` 直接显示每个程序的最后一次改动；agent 换会话后先 `journal` 再动手
- **结论必须可复算**：`note -a` 把"这个函数引用了 Autosave"从一句话变成一条可重算的断言（常量/字符串/导入/调用/大小/字节/符号/名字 八类），`verify` 重新求值。它防的不是恶意，是**自己和 agent 的自信**：我写下 `const=0xffffffff80000001` 时以为对，第一次跑出来是 FAIL，因为 Ghidra 把那个常量存成了负数。

`scan --writes` 只认真正写入内存的指令：`CALL/JMP/PUSH/CMP/TEST/BT/LEA` 的第一个操作数不算写（否则每个间接调用都会冒充字段写者）；位移按**数值**比较，`[RCX + R13*0x1 + -0x40]` 不会被当成 `+0x40`。

同一偏移在多套结构体里重复出现时，用逗号一次问几个字段：`ghlab scan BIN 0x168,0x170,0x178 --writes` 只保留**同时**碰到这三处的函数——单偏移在 30 MB 的二进制里必然被噪声淹没。

要认“结构体拷贝”这种形状，用 `--sequence`：`ghlab scan BIN 0x8,0x10,0x18 --sequence --window 24` 要求三个偏移按顺序落在一个 24 条指令的窗口里，命中直接打印整段。全库一遍约 50 秒（6.5M 条指令），先 `--range`/`--func` 缩小范围。

找一串字节（特征码、字符串常量、立即数表）时把偏移换成 `--hex`：`ghlab scan BIN --hex '48 8B ?? 05'`。`??` 是按字节的通配符（半字节通配会直接报错拒绝），搜索走 `Memory.findBytes(addr, mask)`，每命中一次一次 JVM 调用；输出是命中地址、所在段、所属函数和实际字节（`??` 位置会填成真实值）。用 `-n` 限制条数，命中上限即标 `truncated`。

## 开发

```bash
# 单元测试（不需要 Ghidra / daemon）
~/re/.venv/Scripts/python.exe -m unittest discover -s tests -v

# 含 live 测试：daemon 起着且 notepad.exe 已导入时自动启用（否则 skip）
GHIDRA_TEST_BIN=notepad.exe ~/re/.venv/Scripts/python.exe -m unittest discover -s tests -v
```

```
src/ghlab/
  protocol.py   命令表 + 参数校验 + 响应信封（纯 stdlib）
  session.py    Ghidra 侧实现（懒加载 pyghidra）
  server.py     HTTP 前端、pidfile、端口探测
  client.py     客户端（纯 stdlib）
  cli.py        argparse 子命令 + 输出格式化
tests/          test_protocol.py, test_server_client.py（stub session，真 HTTP）
```

## 开发：ruff + ty

```bash
uv tool install ruff ty                  # 一次性
ruff check . && ruff format --check .    # 或者直接 ruff format .
ty check                                 # 类型检查

python -m unittest discover -s tests -q  # 272 个测试里跑 188 个，约 7 秒，不需要 daemon

# 第一档：端到端冒烟，自带样例（40 KB 的 hostname.exe，临时项目，用完即删）
GHLAB_LIVE=1 python -m unittest discover -s tests
# 第二档：依赖某个特定样本（notepad.exe）的断言，需要它已导入
GHLAB_LIVE_RICH=1 GHLAB_URL=http://127.0.0.1:8765/ python -m unittest discover -s tests
```

**为什么分档，为什么不共用样本**：端到端测试跑的是真反编译器。第一档自己找机器上最小的系统二进制
（Windows: `hostname.exe` → `whoami.exe` → `notepad.exe`；POSIX: `/bin/true` → `/bin/ls`，也可以用
`GHLAB_TEST_BIN` 指定），在**临时项目 + 空闲端口**上导入一次，进程退出就停掉——不碰你的项目、
不需要你装任何产品。用它跑完整套要 ~29 秒（其中导入占大头），测试本身 8 秒。

第二档里的断言是从 notepad.exe 上学来的具体事实（`RegSetValueExW` 的调用者、521 个函数），
换个样本就不成立，所以它必须显式开启。默认跑法只跑单元测试：改一行代码后要能在几秒内跑完，
否则没人会跑它。

（此前不分档：一次 `discover` 300 秒，且在没有 WPS 的机器上会因为找不到样本而报错。）

配置写在 `pyproject.toml` 的 `[tool.ruff]` / `[tool.ty.*]`。两条规则值得说明：

- `select` 里带了 `BLE`（禁止裸 `except Exception`）：唯一豁免是 `session.py` 里那些**调用 jpype 反射**的地方，都写了 `# noqa: BLE001` 并注明原因（"a jpype call can raise anything"）。这类豁免是给人看的，不是给检查器看的。
- `[tool.ty.rules] import-not-found = "ignore"`：`ghidra.*` / `jpype` 是 JVM 运行时才存在的模块，静态检查器没有可解析的包。关掉这条之后 ty 仍然抓到了真问题——比如 `_clean_name(callee)` 收到 `str | None`、`progress: io.TextIOBase` 接不住 `sys.stderr`、以及差集排序键的联合类型推断错误。

## 已知坑（都已在这里绕过）

1. **Windows `SO_REUSEADDR` 允许同端口双监听** → 旧进程继续服务旧代码。ghlab 显式关掉 `allow_reuse_address`，第二个实例会直接失败而不是静默接管。
2. `proj.importProgram(str)` 在 jpype 下重载歧义 → 必须 `proj.importProgram(File(path))`。
3. `FunctionManager.getFunction(String)` 不存在（只有 `getFunction(long)`）→ 按符号表找。
4. `Data.hasStringValue()` 在 jpype 下抛异常 → 改为按数据类型名（string/unicode/char）判定，并返回 `defined_data_scanned` 便于诊断。
5. `GhidraProject.openProgram` 会遗留一个未关闭的 transaction，此后 `program.save()` 必报 `Unable to lock due to active transaction`；`project.save(program)` 才能落盘（`_save()` 里做了回退链）。
6. Ghidra 12.2 的 `CommentType` 只有 `EOL/PRE/POST/PLATE/REPEATABLE`，没有 `DECOMPILER`（11.x 有）→ `decompiler` 映射为 `PRE`。
7. JVM 冷启动 30–45s 不可避免：`ghlab start` 会轮询 health 直到就绪；进程内查询才是快的。
8. 环境代理 127.0.0.1:7897 失效会拖垮 pip/uv：`env -u ALL_PROXY -u HTTP_PROXY -u HTTPS_PROXY`。
9. `EmulatorHelper.getTrackedMemoryWriteSet()` 返回的是 `AddressRange`（且偏移落在奇怪的低地址）→ 改用"运行前后对可写块做字节 diff"。
10. P-code 模拟跑到导入 thunk 里必然 `step()` 返回 False 且 `getLastError()` = `Instruction decode failed (invalid memory)`；必须用"最后一个落在 program 内存里的 PC"定位调用点，再从 `[rsp]` 取返回地址继续。
11. `lock` 前缀/x86 atomics 在 12.2 里是 `CALLOTHER "LOCK"`，未实现就直接抛 `Unimplemented CALLOTHER pcodeop (LOCK)` → ghlab 跳过该指令并记录（计数会失真，解密/解析路径通常无影响）。
12. `MemoryMap.getBytes` 只有 `(Address, byte[])` 重载，jpype 下传长度会 `TypeError: No matching overloads` → 必须用 `JArray(JByte)(size)` 做 sink 再转回 `bytes`。
13. **不能直接 `setBytes` 到指令上**：报 `Memory change conflicts with instruction at ...` → 先 `listing.clearCodeUnits(addr, end, False)`，写完再 `DisassembleCommand(addr, None, True).applyTo(p)`。
14. `MemoryBlockDB` 没有 `isWriteable()`（是 `isWrite()`/`setWrite()`），猜错属性名会在**已开启事务之后**抛异常，把 program 卡在未结束事务里，后续所有保存都报 `Unable to lock due to active transaction` → 属性探测要放在 `startTransaction` 之前。
15. 12.2 的 `BookmarkDBManager` 用**字符串**类型名：`setBookmark(Address, String type, String category, String comment)`、`removeBookmark(Bookmark)`（不是按地址+类型删），也没有 `getType`（是 `getBookmarkType(String)`）。
16. `FunctionSignatureParser` 的构造是 `(DataTypeManager, DataTypeQueryService)`（传 `None` 即可），`parse` 要 `FunctionSignature` 而不是 `Function`：`parser.parse(fn.getSignature(), 'int f(char *)')`；且 `C`/`CPP` 解析器类在 12.2 已不存在。
17. `ApplyFunctionSignatureCmd` 不会改函数名 → `set_type` 里要另外 `fn.setName(声明里的名字)`。
18. **给入口符号改名会让 `program.getEntryPoint()` 失效**（digest 的入口链随之变空）→ 别重命名 `entry`；`_entry_chain` 已加名字/可执行段首函数兜底。
19. **常量的符号性不可假定**：反编译里的 `(HKEY)0xffffffff80000001` 到 `getScalar()` 是**负数** long → 断言比较时必须同时试 `value` / `_u64(value)` / 32 位与 16 位截断（`_const_views()`）。
20. **地址字符串没有唯一写法**：`1400019d0` 不带 `0x` 时 `FlatProgramAPI.toAddr()` 认不出来（它不把裸 hex 当地址）→ `_hex_addr()` 统一识别，`_addr`/`_function` 都走它。

21. **PDB 分析没有 2 参 `doAnalysis`**：12.2 只有 `PdbUniversalAnalyzer.doAnalysis(Program, File, PdbReaderOptions, PdbApplicatorOptions, MessageLog, TaskMonitor)`（返回 boolean）；`MessageLog` 没有 `getMessages()`/`getMessageLog()`，取文本用 `str(log)`。坏 PDB 返回 `false` 且函数数不变（干净拒绝），所以 `if ok` 之前不要 `save`。

## License

MIT

**偏移不是事实**：同一个 `+0x178` 在 `ctx` 上是 dword 排版模式，在 `doc` 上是指针。
`ghlab offsets BIN FUN_1813200F0` 直接给出归属：

```
== wpscore.dll FUN_1813200f0 : undefined FUN_1813200f0() (14ms)
   param_1 (param)
         0x128  x1
         0x12c  x1
         0x130  x1
   param_2 (param)
          0x40  x1
```

写结论时把对象名带上（`doc+0x128` 而不是 `+0x128`），否则下一个人会拿它去错的结构体上验证。
