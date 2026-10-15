# cc-clean

Claude Code 环境检查与按确认范围清理的 Agent Skill。当前版本 **v0.2.2**，支持 Codex 和 Claude Code。

从只读检查开始：查清旧账号状态的实际位置、会话与附属文件的关联、需要保留的工作资产；验证备份后，才按用户确认的具体清单执行操作。账号恢复或申诉仍使用官方渠道，本地操作不改变服务端记录。

## 能力

- **Device ID 摘要**：精确识别显式主状态 JSON 中的 `deviceId`、`device_id`、`deviceID`，含嵌套对象与数组；仅记录结构位置、类型和存在性，不记录原值或原值哈希。默认保留，清理前仍需核实、备份校验和具体确认。
- **关联清单**：项目会话、session-env、file-history、debug、todos 的同根 UUID 路径关联，标明证据、未验证原因与保留理由；自动识别项目级 `projects/*/memory` 与 `CLAUDE.md` 为工作资产，不混入未识别会话。不会因 session-env 缺失或项目路径不存在就判定可删。
- **只读 HTML**：离线单文件，支持搜索、类别/关联筛选、分页及审阅清单导出；默认遮罩常见身份与密钥格式（保留带 `@` 的插件文件名后缀），没有删除、应用或恢复接口。
- **验证备份**：SHA-256、基础权限/属主、链接目标、复制前后源一致性及恢复样本；保留 schema 1 备份兼容性。
- **恢复计划与回执**：验证旧备份及恢复前当前备份（支持 `backup --allow-missing` 记录已移除单文件根的缺失前态），生成精确逐文件计划，随后观察恢复结果与全部未选项。helper 不执行恢复、不验证人的授权。

项目历史、`projects/*/memory`、settings、Skills、插件、MCP、hooks 和网关路由默认保留。用户排除的环境不查不改。文件删除、清空历史、修改凭据等动作必须对应真实用户确认；工具输出不代表批准。

## 安装与调用

需要 Python 3.10+，helper 无第三方运行依赖。文件备份支持 macOS / POSIX；Windows 备份需要平台原生实现。

```bash
git clone https://github.com/luwill/cc-clean.git
```

把仓库中的 `cc-clean/` 放到所用 Agent 的技能目录，已有同名技能时先核对并保留旧版本：

| Agent | 技能位置 | 调用 |
|---|---|---|
| Codex | `~/.codex/skills/cc-clean/` | `$cc-clean` |
| Claude Code | `~/.claude/skills/cc-clean/` | `/cc-clean` |

也可让 Claude Code 的技能入口链接到同一份 Codex 技能代码。自定义配置目录的发现规则需按实际环境核实。若在**目标环境的活跃 Claude Code 会话内**直接调用 `/cc-clean`，当前会话内仅执行只读检查（`audit` / `report`）与计划确认；涉及全树静止校验的备份、`verify --check-source`、清理和恢复，应在退出目标 Claude 会话后从外部环境（如 Codex `$cc-clean` 或独立配置目录）执行。

示例请求：

> 用 cc-clean 对指定 Claude 目录和主状态文件做只读检查，保留项目历史和工作配置，排除指定网关目录，生成关联清单和 HTML 报告。不删除或修改源数据。

## 直接运行只读 helper

先创建位于源目录之外、且不含符号链接祖先的私有报告目录（macOS 下 `/tmp`、`/var` 为系统软链接，请使用 `/private/...` 真实路径或主目录下新建的私有目录）；下面的 `OUTPUT_DIR` 请换为明确选择的绝对路径。

```bash
python3 -B cc-clean/scripts/local_state.py audit \
  --root default="$HOME/.claude" \
  --root state="$HOME/.claude.json" \
  --state-file "$HOME/.claude.json" \
  --output "$OUTPUT_DIR/audit.json"

python3 -B cc-clean/scripts/local_state.py report \
  --audit "$OUTPUT_DIR/audit.json" \
  --output "$OUTPUT_DIR/report.html"
```

audit 只记录文件元数据，不读取凭据或历史正文。主状态 JSON 只有显式指定 `--state-file` 时才读取，输出字段摘要；device ID 的嵌套位置用从 0 开始的对象键序号与数组下标，不保留可能夹带身份信息的祖先键名。空值也算字段存在，不推断有效性或账号归属；解析失败、重复 JSON 键或缺少递归检查摘要时不宣称全局没有 ID。扫描不展开字符串/编码内容、不读取其他文件正文、不获取或重置系统硬件 ID。HTML 只读取提供的审计文件，不重新访问环境。原始 JSON 与 HTML 都以 0600 创建；路径与未知格式文件名仍可能是私密信息，真实报告应留在本地，分享前复核。

详细规则见 [技能入口](cc-clean/SKILL.md)、[关联/报告/恢复说明](cc-clean/references/review.md)、[确认清单与操作](cc-clean/references/operations.md)。

## 检查与测试

```bash
make check
```

执行源码格式/语法/引用检查与 **67 项虚构数据测试**。不会访问真实 Claude 目录、Keychain、进程环境或网络；测试样本保留在被 Git 忽略的 `test-artifacts/` 中，不自动删除。HTML 的 JavaScript 语法检查需要 Node.js。

仅包含技能、说明与测试代码。真实审计、原始历史、凭据、备份、安装回执和本机路径清单不应提交到仓库。
