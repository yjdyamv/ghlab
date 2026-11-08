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
ghlab bytes notepad.exe 0x1400019d0 --size 32
ghlab rename notepad.exe FUN_140001008 sub_parse_cmdline
ghlab comment notepad.exe 0x1400019d0 'entry stub -> 0x140001850'
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
| `decompile` | `binary` / `targets, target, match, grep, limit, max_lines, include_code, include_callees, include_callers, timeout` | 单个 / 批量 / 服务端 grep |
| `strings` | `binary` / `query, limit, offset` | 字符串数据搜索 |
| `xrefs` | `binary` / `target, targets` | 引用（谁引用了它） |
| `bytes` | `binary, addr` / `size` | 原始字节 hex+ascii |
| `rename` | `binary, target, new` | 重命名并保存 |
| `comment` | `binary, target, text` / `type` | 写注释并保存（type: plate/pre/post/eol，默认 plate；`decompiler` → pre） |
| `graph` | `binary, target` / `direction, depth, limit` | 调用树 BFS |
| `digest` | `binary` / `top, strings` | **一次性 triage**：入口链、按风险分组的导入、API 组合、字符串分类、调用图枢纽、函数大小分布（实测 notepad ≈450 token / 2.7s） |
| `find` | `binary` / `import, string, calls, limit, any` | **按结构定位候选**：谁调用了这些导入 / 引用了这些字符串 / 调用了这些函数（默认全部条件同时成立，`--any` 取或） |
| `emulate` | `binary, target` / `args, max_insns, ms, buffer, dump` | **P-code 模拟执行**：按 Win64 约定播种参数（`123`/`0x40`/`"str"`/`L"wide"`/`*symbol`），自动应答 memset/memcpy/strlen/strcpy 等 CRT 调用，未实现的导入返回 0，回传返回值、可写内存 diff、`--buffer` 内容、停止原因 |

`target` 可以是符号名或 `0x` 地址；`binary` 支持唯一子串匹配。
写操作（rename/comment）放在 Ghidra transaction 里并立即 `program.save()`。

## 设计要点

- **常驻 + 项目落盘**：`~/re/proj/ghlab` 是普通 Ghidra 项目，Ghidra GUI 也能打开看，两边结果一致。
- **单线程 server**：Ghidra 的 transaction 不是线程安全的，串行执行换来"永不损坏项目"。
- **服务端过滤**：`grep` 在 daemon 侧执行，只回传 `{line, text}`，几百个函数的扫描也只占几百 token。
- **零依赖**：`protocol.py`/`client.py` 只用 stdlib，`session.py` 才懒加载 pyghidra → 单元测试和 CLI 都能在没有 Ghidra 的机器上跑。
- **协议自描述**：`GET /` 返回全部命令及其参数，agent 可自举。
- **模拟执行是"够用主义"**：`EmulatorHelper` 在独立内存里跑，写入不落回 program；外部导入用 Python 应答（CRT 真的有语义，其余返回 0），`lock` 等未实现的 p-code op 直接跳过并在输出里点名。所以它适合解密循环、配置解析、返回值推演，不适合依赖真实 API 语义的逻辑。

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

## License

MIT
