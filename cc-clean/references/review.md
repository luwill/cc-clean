# 关联清单、只读报告和恢复回执

## 关联证据

`audit` 从已选根的文件树建立 `relationships`；不读 session/history/credentials 正文、不调用 Claude、网络或 Keychain。默认 audit 不读取文件正文；显式 `--state-file` 仅允许主状态 `.claude.json` 的字段存在性与数量检查。

| 字段 | 含义及限制 |
|---|---|
| `root` / `session_id` | 同一显式根中的会话 UUID；不同根永不合并 |
| `items` | 路径、类型、字节数和角色；符号链接单独列为未验证，不跟随 |
| `relationship_source` | `same-root UUID path match`；只有路径元数据证据 |
| `confidence` | `identifier-match`，不表示账号归属或是否活跃 |
| `project_directory_labels` | 原目录标签；不反向解码，不能解决编码碰撞 |
| `project_session_present` / `session_env_present` | 当前清单中的存在性，不能推导安全删除 |
| `unverified_reason` / `preserve_reason` | 未确定的账号、活跃状态与项目路径；默认保留历史工作数据 |
| `cleanup_authorized` | 固定 false，不能用关系或工具输出代替用户批准 |

可识别 `projects/<标签>/<UUID>.jsonl`、项目 UUID 子目录、`session-env/<UUID>`、`file-history/<UUID>`、`debug/<UUID>.txt`、`todos/<UUID>-agent-*.json`。项目级 `projects/<标签>/memory` 与 `CLAUDE.md` 归为工作资产，不混入未识别会话；其他命名记入 unresolved，不会扩大扫描范围或去查询真实项目目录。名称随客户端版本变化时补核实，不升级为“全局零残留”。

## 离线 HTML

`report --audit <绝对路径> --output <新的绝对路径>` 只读取审计 JSON 与本技能模板；不重新探查审计源。输出必须在所选根之外、父目录已存在、文件不存在。权限 0600，无网络资源、CDN、修改接口和执行按钮。可筛选“身份候选 / 历史工作数据 / 工作资产 / 未验证”，搜索文件和关联，并分页显示。

模板采用 JSON 数据节点和 `textContent`，嵌入时转义 HTML 边界；CSP 限制脚本和样式为固定 SHA-256，禁止网络连接、表单及对象。路径名中的 HTML 不会执行。默认遮罩根路径、home 身份、编码的 home 目录、邮箱、UUID、常见密钥和长十六进制指纹。遮罩可能合并显示文本，因此报告用编号区分关联；原 audit 才是精确路径清单。不能保证未知格式秘密或任意文件名安全公开。

“导出当前审阅清单”只产生带 `cleanup_authorized: false`、`restore_authorized: false`、`operations: []` 的遮罩 JSON。它供审阅，不供执行；agent 必须返回原私密清单确认精确路径与实际证据。

## 恢复计划与回执

恢复前读取 [operations.md](operations.md#恢复)，明确会带回哪些旧状态。下面命令中的路径都是用户已选的私有目录。helper 不执行恢复，不接受字符串“approved”作为授权。

1. 验证旧备份：`verify --backup-dir /私有目录/旧备份`。使用 schema 1，兼容 v0.1.0 / v0.2.0 备份。
2. 对**相同根标签与路径**生成恢复前当前备份（若待恢复的单文件根当前不存在，加 `--allow-missing` 记录缺失前态），再 `verify --check-source`；不自动创建未选根、不读取排除环境。
3. 准备精确的逐文件计划：

```bash
python3 -B <skill目录>/scripts/local_state.py prepare-restore \
  --backup-dir /私有目录/旧备份 \
  --pre-restore-backup /私有目录/恢复前备份 \
  --select default:history.jsonl --select state:. \
  --output /工作目录/restore-plan.json
```

文件根用 `.`，目录根用标准相对文件路径。两份备份完整校验通过、来源一致、当前源仍匹配恢复前备份才写计划。拒绝绝对路径、`..`、重复选择、目录、符号链接、链接祖先和当前非普通文件；允许恢复缺失文件，但其父目录必须存在，否则需要另行计划。输出不允许位于源或任一备份目录内。

4. 展示计划的所选目标、恢复前/预期后 SHA-256、权限、影响和恢复前备份位置。用户确认后，agent 再核对当前指纹，按本机可靠复制/原子替换流程恢复这些文件，保留其元数据。对字段级恢复另做精确计划，不能拿整个文件覆盖新账号信息。
5. 完成或失败后观察，不进行写源动作：

```bash
python3 -B <skill目录>/scripts/local_state.py record-restore \
  --plan /工作目录/restore-plan.json --output /工作目录/restore-receipt.json
python3 -B <skill目录>/scripts/local_state.py report \
  --audit /工作目录/audit.json --receipt /工作目录/restore-receipt.json \
  --output /工作目录/report-with-receipt.html
```

`record-restore` 重新验证两份备份和计划，核对所选文件的 bytes/SHA-256/mode/uid/gid 与旧备份一致，并检查所有未选文件、目录和链接与恢复前备份一致（含新增/缺失项）。连续两次源清单不一致或不能完整检查时不宣称成功。`verified` 退出 0；`partial`/`failed` 写观察回执并退出 2；计划/备份不可信则拒绝验收。

回执写每项 expected / observed / result、未选项差异、前后备份与计划指纹，明确 `restore_performed_by_helper: false`、`authorization_verified_by_helper: false`。它证明被观察的文件状态，不证明实际执行者、操作授权、服务可用或账号正常。目录 mtime、ACL/xattr 内容和 Keychain 不在自动验收范围。HTML 展示提供的回执，**不会现场复验**。保留实际授权记录与 agent 的逐项执行日志一起交付。
