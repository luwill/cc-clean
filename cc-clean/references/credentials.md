# 凭据与环境边界

只在任务涉及账号凭据、网关、平台差异或需要证明环境独立时读取。下列实现线索来自 2026-10-12 对 Claude Code 2.1.296 的检查；新版必须以当下文档及本机实现核实，不固定照搬。

## 查明真正的认证来源

配置中看到旧账号不等于当前模型请求还用它。检查 `ANTHROPIC_API_KEY`、`ANTHROPIC_AUTH_TOKEN`、`CLAUDE_CODE_OAUTH_TOKEN` 是否存在，`ANTHROPIC_BASE_URL` 去掉用户信息、query 后的 endpoint，以及 `apiKeyHelper` 的配置存在性。只读检查时不运行 helper，也不调用 token 刷新接口。

本地路由器有自己的 `.env` 和模型配置。用户要求保留网关时，先确定路由器使用供应商 Key 还是 Claude OAuth；不要把客户端用于访问本地代理的占位认证值误认为供应商秘密。仍在用的路由配置、Key 和 Key 备份，不因带有旧时间戳而自动删除。

共享 Skills 链接、状态栏脚本、插件安装路径或 hooks 可能跨目录引用。独立配置目录不等于所有文件都独立。若用户明确排除该环境，只说明无法验证跨环境依赖，不突破排除范围去检查。

## macOS Keychain

官方认证文档说明凭据使用系统钥匙串；钥匙串不可写时可能退回配置目录下 `.credentials.json`。两处都列入存在性检查。

元数据检查使用 `security find-generic-password` 的准确 service、account、keychain，**不加 `-g` 或 `-w`**。错误码 44/明确 item-not-found 才能据此报告没有对应项；权限、锁定、调用参数或 sandbox 错误属于未验证。只查用户范围内的命名空间，不 `dump-keychain`，不读数据库，不批量删除所有 Claude 名称项。

本机 2.1.296 的默认 service 曾为 `Claude Code-credentials`，显式配置目录还可能有路径派生 suffix；`CLAUDE_SECURESTORAGE_CONFIG_DIR` 覆盖值可能让两个目录共用存储。空覆盖值也要区分。service、account、keychain 路径必须查实；账户缓存 email 与 Keychain payload 的账号归属不能仅凭日期推断。

一个 JSON bundle 可能含 `claudeAiOauth`、`mcpOAuth` 等子项。整项删除可能清掉 MCP 登录/客户端注册缓存。计划须明确选“整项删除”或“仅移除已确认子项”，并列影响和恢复方式。若只需要退出 Claude 而要保留 MCP，优先检查可否仅移除 `claudeAiOauth`。

读取秘密 payload 需要对应 named item 的明确授权；只在本地内存里解析，输出 root key、子项计数、秘密字段是否存在与同值比较结果，不输出 token、client secret 或整个 JSON。更新时经 stdin 或不产生 shell 明文参数的安全本地 API 输入，避免在 shell 历史、进程参数和工具结果中再次留 token。使用 `security ... -w <明文>` 将完整秘密放到 argv 的方式不适合 bundle 更新。

变更凭据前建立明确恢复路径。可以在用户批准下生成权限 0600 的本地恢复材料，也可在用户明知需要重新登录后采用不可恢复的删除；文件目录备份不包含 Keychain，不能伪称已备份。恢复材料、任何临时 payload 文件和旧备份也在敏感范围内；不得自行上传或删除。

## Linux / Windows / profiles

官方文档：Linux 和 Windows 通常用配置目录的 `.credentials.json`，Linux 模式为 0600，Windows 依赖用户 ACL。只移除已确认的旧认证子项，保留其他用途的字段。Windows 辅助脚本当前不执行 ACL 验证；使用平台原生备份和权限检查，不把 POSIX 模式结论套过去。

新版 Console 无 API Key 登录可能以 Anthropic profile 存储，独立 `CLAUDE_CONFIG_DIR` 不保证该路径隔离。使用官方认证文档核实当下的 profile 位置、退出撤销行为及共享影响；本机未核实的命名空间不自动处理。

普通账户切换可用官方 `/logout` 或当前版本 CLI 的 auth logout；它会改状态，并可能撤销服务端凭据，不属于只读探测。不能为了“看下现在是谁”启动旧账号请求。组织管理配置不因换账号而删除。
