# ghlab

**一个常驻的 Ghidra，透过一个极小的 JSON/HTTP 接口暴露给 agent 和脚本。**

Ghidra 的分析能力很强，但每次 `analyzeHeadless` 冷启动 30–45 秒、无法增量重用结果，agent 交互式逆向基本不可行。
ghlab 把 Ghidra 的 headless JVM 变成**常驻进程**：一次导入、分析落盘，之后每次查询 0.1–2.5 秒，而且天生支持"批量反编译 + 服务端过滤"，非常适合 LLM 上下文有限的场景。

```
agent / shell / 脚本
        │  POST {"cmd": "decompile", "binary": "notepad.exe", "match": "WinMain", "grep": "CreateWindow"}
        ▼
  ghlab daemon (常驻, 单线程)  ──→  Ghidra 12.x headless  (pyghidra 3.2 / jpype 1.5)
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

# 3. 启动
export GHIDRA_INSTALL_DIR="$GHD"     # Windows: setx GHIDRA_INSTALL_DIR C:\ghidra_12.2_PUBLIC
ghlab start                          # 后台常驻，日志 ~/re/logs/ghlab.log
ghlab status
```

Linux/macOS 同理，把 `Scripts/python.exe` 换成 `bin/python`。

## 用法

```bash
ghlab import C:/Windows/System32/notepad.exe   # 导入 + 全量分析（约 75s，仅一次）
ghlab binaries
ghlab info notepad.exe

ghlab functions notepad.exe -m 'WinMain|WndProc'
ghlab decompile notepad.exe -t entry           # 单个，完整源码
ghlab decompile notepad.exe -t FUN_140001008 --max-lines 30

# 批量：把每个 FUN_* 都反编译，只回传命中的行（省 context 的关键）
ghlab decompile notepad.exe -m 'FUN_' -g 'CreateWindow|RegisterClass|GetDlgItem' -n 40

ghlab strings notepad.exe -q txt

# 先看全局，再决定花 token 看哪里
ghlab digest notepad.exe

# 按结构缩小候选集：谁既写注册表又碰 Notepad 字符串
ghlab find notepad.exe -i RegSetValue -s Notepad
ghlab find notepad.exe -i 'VirtualAlloc|VirtualProtect' --any -n 10

ghlab xrefs notepad.exe entry
ghlab graph notepad.exe entry -d 2                # 调用树
ghlab graph notepad.exe entry --direction called   # 调用者树

# 让函数跑一遍（P-code 模拟，不落盘）：给定参数，看它返回什么、写了哪块内存
ghlab emulate notepad.exe __security_check_cookie --arg 1
ghlab emulate notepad.exe FUN_140007e1c --arg 1 --arg '"hello"' --buffer 64
ghlab emulate notepad.exe decrypt_config --arg 0x140038600 --buffer 256 --ms 8000

# 两个版本比功能差异（字符串/导入/常量/CFG 形状匹配，不靠地址对齐）
ghlab import C:/samples/app_v1.exe && ghlab import C:/samples/app_v2.exe
ghlab diff app_v1.exe app_v2.exe
ghlab diff app_v1.exe app_v2.exe -m 'decrypt|auth' -n 10
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

# 跨程序：哪个样本也连这个域名？这个 API 是由哪条路径走到的？这段逻辑在别的样本里叫什么？
ghlab cross-xref 'autosave'                       # 全项目搜字符串，附"谁在用"
ghlab slice notepad.exe RegSetValueExW            # 从入口到该导入的最短调用链
ghlab similar notepad.exe FUN_140021ba8 --against other.exe
```

任何命令加 `--json` 得到原始结构；`GHLAB_URL=http://host:port` 可指向远端 daemon。
不带参数直接 `POST` 也行：

```bash
curl -s localhost:8765/ -d '{"cmd":"decompile","binary":"notepad.exe","targets":["entry"],"include_callees":true}'
curl -s localhost:8765/ | jq          # 自描述的命令表
```

## 命令一览

| cmd | 参数（必填 / 可选） | 说明 |
|---|---|---|
| `ping` | – | 存活 + 项目信息 |
| `binaries` | – | 项目内程序 |
| `import` | `path` / `analyze` | 导入并分析 |
| `info` | `binary` | 语言、基址、MD5、函数数、段 |
| `functions` | `binary` / `match, limit, offset` | 按名过滤列函数 |
| `decompile` | `binary` / `targets, target, match, grep, limit, max_lines, include_code, include_callees, include_callers, timeout, refresh` | 单个 / 批量 / 服务端 grep；结果按 `md5+地址+签名+注释` 缓存到 `<项目>/.ghlab/cache`，热查询 2.5s → 0.19s，`--refresh` 强制重算 |
| `strings` | `binary` / `query, limit, offset` | 字符串数据搜索 |
| `xrefs` | `binary` / `target, targets` | 引用（谁引用了它） |
| `bytes` | `binary, addr` / `size` | 原始字节 hex+ascii |
| `rename` | `binary, target, new` | 重命名并保存 |
| `comment` | `binary, target, text` / `type` | 写注释并保存（type: plate/pre/post/eol，默认 plate；`decompiler` → pre） |
| `graph` | `binary, target` / `direction, depth, limit` | 调用树 BFS |
| `digest` | `binary` / `top, strings` | **一次性 triage**：入口链、按风险分组的导入、API 组合、字符串分类、调用图枢纽、函数大小分布（实测 notepad ≈450 token / 2.7s） |
| `find` | `binary` / `import, string, calls, limit, any` | **按结构定位候选**：谁调用了这些导入 / 引用了这些字符串 / 调用了这些函数（默认全部条件同时成立，`--any` 取或） |
| `emulate` | `binary, target` / `args, max_insns, ms, buffer, dump` | **P-code 模拟执行**：按 Win64 约定播种参数（`123`/`0x40`/`"str"`/`L"wide"`/`*symbol`），自动应答 memset/memcpy/strlen/strcpy 等 CRT 调用，未实现的导入返回 0，回传返回值、可写内存 diff、`--buffer` 内容、停止原因 |
| `diff` | `a, b` / `match, limit, min_score` | **功能级差异**：每个函数提取（引用的字符串、外部导入、常量、指令/块/调用数），四轮匹配（签名唯一 → 同地址 → 同名 → 相似度贪心），输出 added/removed/changed + 段 hash 差异（实测 521 函数两边共 2–4s，命中缓存的重复查询 <0.1s） |
| `patch` | `binary, addr` / `bytes, nop, expect` | **真打补丁**：先 `clearCodeUnits` 再写（否则 Ghidra 报 `Memory change conflicts with instruction`），随后重新反汇编并落盘；只读段会临时置写。`--expect` 长度必须与写入等长 |
| `set_type` | `binary, target, decl` | **写类型**：`'int f(char *s, unsigned n)'` 走 `FunctionSignatureParser`（名字以声明为准），`'char[64]'`/`'void*'`/`'DWORD'` 走 `CreateDataCmd` |
| `bookmark` | `binary` / `action, addr, target, type, category, comment, limit` | Ghidra 书签 add/list/remove（GUI 里能直接看到，类别当分组用） |
| `note` | `binary, text` / `at, tag` | 追加一条结论：写 `<项目>/.ghlab/notes/<binary>.json` + 同名书签 |
| `notes` | `binary` / `tag, at, query, limit` | 按标签/位置/关键词检索结论 |
| `cross-xref` | `query` / `binary, limit` | **跨程序**搜字符串数据，附每个命中的引用者；省掉"逐个程序 decompile 找字符串" |
| `slice` | `binary, to` / `from, depth, limit, code` | **反向切片**：沿调用者 BFS 到 entry/main/WinMain/DllMain，给出"什么条件下这个 API 会被调用"的链；`--code` 附调用者反编译 |
| `similar` | `binary, target` / `against, limit, min_score` | **跨程序同构函数**：字符串/导入/常量/大小四路指纹打分；零特征的 thunk 一律压到 0.3 以下，避免 stub 互相当成 1.00 |
| `report` | `binary` / `top` | Markdown 报告：digest 摘要 + 调用图枢纽 + 函数大小分布 + 按标签分组的结论，可直接贴进报告 |

`target` 可以是符号名或 `0x` 地址；`binary` 支持唯一子串匹配。
写操作（rename/comment）放在 Ghidra transaction 里并立即 `program.save()`。

## 设计要点

- **常驻 + 项目落盘**：`~/re/proj/ghlab` 是普通 Ghidra 项目，Ghidra GUI 也能打开看，两边结果一致。
- **单线程 server**：Ghidra 的 transaction 不是线程安全的，串行执行换来"永不损坏项目"。
- **服务端过滤**：`grep` 在 daemon 侧执行，只回传 `{line, text}`，几百个函数的扫描也只占几百 token。
- **零依赖**：`protocol.py`/`client.py` 只用 stdlib，`session.py` 才懒加载 pyghidra → 单元测试和 CLI 都能在没有 Ghidra 的机器上跑。
- **协议自描述**：`GET /` 返回全部命令及其参数，agent 可自举。
- **模拟执行是"够用主义"**：`EmulatorHelper` 在独立内存里跑，写入不落回 program；外部导入用 Python 应答（CRT 真的有语义，其余返回 0），`lock` 等未实现的 p-code op 直接跳过并在输出里点名。所以它适合解密循环、配置解析、返回值推演，不适合依赖真实 API 语义的逻辑。
- **diff 不假设地址对齐**：指纹是"这个函数引用了哪些字符串/调用了哪些导入/用了哪些常量/多大/多少块"，匹配时先找签名唯一的，再退同地址（同基址补丁）、同名（有符号）、最后相似度贪心（阈值 `--min-score`）。所以既能比同源补丁，也能比隔了几个版本的构建。
- **缓存键里不放指令字节**：第一次反编译会重写 code unit，反编译前算的哈希和之后算的永远不等，所以键用 `md5+地址+函数签名+注释`；打完补丁要 `--refresh`。
- **相似度必须防 stub 噪声**：几百个 29 字节 thunk 的空指纹两两相似度都是 1.00，所以"没有任何共享字符串/导入/常量"的候选一律压到 0.3 以下。
- **写操作全部落盘、全部可校验**：`patch` 要求 `--expect` 长度与写入一致（防手滑写错位置），改完重新反汇编；`set_type` 以声明里的名字为准；`note` 同时写 Ghidra 书签和磁盘 JSON——书签给 GUI 用户看，JSON 给 agent 和 `report` 用，两边不互相依赖（Ghidra 崩了结论还在）。

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

## License

MIT
