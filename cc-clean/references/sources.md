# 来源与本机验证依据

核对日期：2026-10-14。维护时按主题更新来源，不带入真实邮箱、UUID、凭据、原始日志或主机用户名。本技能独立实现脚本，没有复制上游 Rust 代码。

## claude-code-cleaner

仓库：[garrickz2/claude-code-cleaner](https://github.com/garrickz2/claude-code-cleaner)。本次源码 revision：`e7a0abfbfd831d7d4f9fb652917ca6c156291471`。

| 源码位置 | 核对结果 | 对本技能的影响 |
|---|---|---|
| `src/main.rs` 的 run_app | 固定使用 home 下 `.claude` | 不把它作为自定义配置目录的账号处理器。 |
| `src/model/settings.rs` | 初始 expiry 30 天、dry_run false | 不启动 TUI 当只读检查；不能假设默认 dry run。 |
| `src/model/category.rs` | 默认选全部类别，plugins 也在类别中；protected 包含 settings、skills 和凭据文件等 | 保护项不满足本任务保留 plugins/rules/hooks/历史的全部需求。 |
| `src/cleaner/mod.rs` | 直接移除文件；孤立项目可删整个缓存；history 保留最后 500 行；临时文件 rename 改配置 | 不采用按年龄/原路径缺失自动删的策略，历史默认保留。 |
| `src/scanner/categories.rs` | 选定缓存与项目指标字段处理；名单不含 oauthAccount/userID/machineID | 磁盘整理不能替代账号标识和凭据处理。 |
| `src/model/settings.rs`、`src/main.rs` | 运行流程保存 cleaner-preferences.json | 其 dry run 不宜被称作完全不写环境；本 helper 输出在明确选择的目录之外。 |

借鉴它的扫描、选择、预览、执行分段和保护思路。清理器若未来版本增加账号或自定义目录支持，应重新读源码；不要把本次观察写成永久限制。

## CC-Cleaner 的关联与审阅思路

仓库：[tk-425/CC-Cleaner](https://github.com/tk-425/CC-Cleaner)，本次只读源码核对 revision：`5119fb2a2ace5aa35eff5bb52eba3da9e51aa95e`，package 1.1.0。

- `server.js` 的 `getSessionUuidsForProject`、`getRelatedSessionEnvs`、`getRelatedFileHistory` 提供项目→会话→附属数据的关联思路。本技能独立实现同根 UUID 元数据关联，并明确保留所有未验证历史数据。
- 恢复前保存当前配置是有用的工作流；本技能要求恢复前备份完整验证、逐文件选择、真实用户授权和未选项验收。
- 分类、搜索和预览界面适合只读审阅；本技能输出单文件离线 HTML，没有清理或恢复网络接口。

没有复用上游源码或启动服务。没有沿用“只因 session-env 不存在就判定孤儿”、有歧义的项目路径解码、跟随符号链接的递归复制、忽略子复制失败、仅按字符串前缀限制备份路径或启动即写入环境的行为。上述是该固定 revision 的观察，维护时重新核实。

## 官方资料

- [Authentication](https://code.claude.com/docs/en/authentication)：官方退出、配置目录隔离、平台凭据与 Console profiles 的限制。Keychain namespace 实际名称仍需本机核实。
- [Claude directory](https://code.claude.com/docs/en/claude-directory)：项目状态和 purge 范围。purge 会影响会话/记忆/历史，不是旧账号凭据清理的替代入口。
- [Environment variables](https://code.claude.com/docs/en/env-vars)、[Data usage](https://code.claude.com/docs/en/data-usage)、[Remote Control](https://code.claude.com/docs/en/remote-control)：只在配置采集开关时重查当前语义和功能影响。
- [Safeguards, warnings, and appeals](https://support.claude.com/en/articles/8241253-safeguards-warnings-and-appeals)：账号被限制时使用官方申诉流程，本地数据操作不决定申诉结果。

## 设计中的实测依据

以下来自 2026-10-10 至 2026-10-12 一次 macOS Claude Code 2.1.296 的审计与授权操作，作为方法依据，不作为未来机器的固定清单：

- 9 个遥测文件包含 238 条 JSONL 事件，部分 metadata 为 Base64 JSON；有标识字段却不能证明服务器收到或封禁因果。
- 完整备份 18,276 个普通文件与 11 个符号链接后，只删除确认的 20 个文件和主配置 12 个字段，保留项目、MCP 和工作资产。
- 文件中的旧账号缓存已移除，但默认系统 Keychain 仍有凭据；准确项另行获授权后才处理。
- 独立网关凭据 bundle 同时包含旧 Claude OAuth 和两个 MCP 缓存，按子项处理后保留路由器认证配置。
- 860 条输入历史中两条含供应商密钥；先退出正在写入的会话再定点替换，858 行保持字节一致，未轮换密钥。

修订后的文章把运营指标、错误报告、主动反馈和不同开关的 Remote Control 条件进一步区分。该稿件是经验材料，更新技能中的功能规则仍引用当下官方文档。
