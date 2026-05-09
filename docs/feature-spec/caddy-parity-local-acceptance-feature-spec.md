# StellarGate Caddy Parity / 自动 SSL 本地验收 Feature Spec

## Convergence Summary

- **Confirmed goal:** 对本次 StellarGate Caddy parity / 自动 SSL 变更做本地完整验收，发现问题按 TDD 修复，最终全部 pass。
- **Confirmed requirements:** 先 CI 验收，再构建运行服务做 API 验收，再做浏览器网页验收，最后 subagent review。
- **Known scope boundaries:** 本轮以本地/Pebble/浏览器闭环为准，不直接改线上 tx2、不推送、不发 tag，除非用户后续明确要求。
- **Relevant system context:** Rust + Pingora gateway；支持 Caddyfile 子集、apex/wildcard 路由、HTTP-01、TLS-ALPN-01、ask policy、cert cache。
- **Working assumptions:** 浏览器无法直接设置 Host header，网页验收使用本地 helper proxy 或等价解析方式转发到 gateway 并设置 Host。
- **Blocking questions:** 无；验收路径可按安全默认假设执行。
- **Readiness score:** 94/100，mission-ready。

## Goal

验证 StellarGate 当前实现是否达到本次变更目标：Caddyfile-like 配置、apex/wildcard 路由、unknown host 拒绝、Host/X-Forwarded-Host 保真、HTTP-01 运行时响应、TLS-ALPN-01 自动 SSL 路径、ACME account/cache/reload 关键闭环全部本地通过。

## Scope

### In scope

- CI 全量验证：格式、clippy、单元/集成测试、Docker/Pebble acceptance。
- 构建运行：release 或 Docker image 能启动 gateway，加载本地 Gatewayfile。
- API 验收：health、metrics、apex/wildcard routing、unknown host rejection、forwarded host overwrite、ACME challenge 行为。
- 网页验收：用 agent-browser 打开本地代理后的页面，验证主站、租户、unknown host 页面/状态。
- 修复策略：遇到失败必须按 TDD，先写/定位失败测试，再最小实现修复，再重跑相关验证。
- 最终 review：使用 subagent 独立检查本次实现和验收结果是否还有遗漏。

### Out of scope

- 不做生产 tx2 切流、真实 Let's Encrypt 再尝试、DNS 修改、GHCR push/tag。
- 不重写全量文档，除本 spec 及必要测试/代码修复外不做无关 cleanup。
- 不把浏览器验收扩展为业务网站 CMS 全量 E2E；本 mission 验收 gateway 行为。

## PRD Requirements

- **FR-001:** CI 验收必须覆盖 `cargo fmt --check`、`cargo clippy --all-targets --all-features`、`cargo test`。
- **FR-002:** Docker/Pebble acceptance 必须验证本地 ACME 自动签发、cert cache、reload/restart 行为。
- **FR-003:** 运行态 API 验收必须证明 `hdd.ink` apex 和至少两个 tenant hosts 能代理到 upstream。
- **FR-004:** 运行态 API 验收必须证明 `example.com` 等 unknown host 被拒绝且不触达 upstream。
- **FR-005:** upstream 必须收到被接受的原始 Host，且 spoofed `X-Forwarded-Host` 被覆盖。
- **FR-006:** HTTP-01 active challenge 必须在 gateway 层返回 key authorization，不走 upstream。
- **FR-007:** TLS-ALPN-01 support 必须在本地编译/测试/acceptance 中不破坏既有 ACME 闭环，并由代码测试覆盖关键路径。
- **FR-008:** 网页验收必须通过 agent-browser 产生可复现证据，覆盖 apex、tenant、unknown host。

## Technical Plan

- 使用 `/Users/chenwenjie/stellarlink/stellar-gateway` 作为执行目录。
- 先检查当前 git 状态，记录非本任务已有未跟踪目录但不删除。
- 执行 CI：`cargo fmt --check`、`cargo clippy --all-targets --all-features`、`cargo test`。
- 执行 acceptance：`python3 tests/acceptance/docker_compose_acceptance.py`。
- 构建运行本地服务：启动 test upstream、ask server、gateway，使用临时 Gatewayfile/Caddyfile subset。
- API 验收用 curl/TCP：health、metrics、apex、tenant、unknown、X-Forwarded-Host overwrite、HTTP-01 path。
- 浏览器验收用 agent-browser：通过 helper proxy 将 `/apex`、`/tenant/<name>` 或不同本地端口映射到 gateway Host headers。
- 若失败，进入 TDD loop：新增/调整最小失败测试 -> 修复 -> scoped test -> full validation。
- 最终 subagent review：让独立 agent 检查 diff、测试覆盖、验收证据和残余风险。

## Acceptance Criteria

- **AC-001:** CI 命令全部 exit 0，无格式、lint、测试失败。
- **AC-002:** Docker/Pebble acceptance exit 0，证明本地自动 SSL 闭环可运行。
- **AC-003:** 运行态 API 验收报告包含每个 host/path 的 status、body marker、upstream request evidence。
- **AC-004:** 浏览器验收报告包含 agent-browser snapshot/文本证据，证明 apex/tenant 页面可访问、unknown host 被拒绝。
- **AC-005:** 若发生修复，最终相关回归测试与全量验证均通过。
- **AC-006:** subagent review 未发现 blocking 问题；若有非 blocking 风险，最终总结明确列出。

## Validation Plan

- **VAL-001:** `cargo fmt --manifest-path Cargo.toml --check` -> pass。
- **VAL-002:** `cargo clippy --manifest-path Cargo.toml --all-targets --all-features` -> pass。
- **VAL-003:** `cargo test --manifest-path Cargo.toml` -> pass。
- **VAL-004:** `python3 tests/acceptance/docker_compose_acceptance.py` -> pass。
- **VAL-005:** Local run API smoke -> health 200, metrics 200, apex/tenant 200, unknown 404, forwarded host overwritten。
- **VAL-006:** Browser smoke via agent-browser -> apex/tenant visible content, unknown rejection visible。
- **VAL-007:** Subagent review -> no blocking issues。

## Agent Execution Contract

- **Deliverables:** validation command log summary, API smoke evidence, browser evidence, fixes if required, final review result。
- **Required behavior:** preserve existing routing/ACME behavior; do not weaken ask policy or host isolation。
- **TDD rule:** no production fix without a failing or targeted regression test first when behavior is testable。
- **Safety:** do not modify production servers, DNS, GHCR, git tags, or push remotes during this mission。
- **Evidence format:** concise final summary with commands and pass/fail, plus files changed if any fixes are made。

## Mission Handoff

- **Mission goal:** 完成本地 CI + runtime API + browser + review 验收闭环，必要时按 TDD 修复。
- **Suggested slices:**
  1. CI validation.
  2. Docker/Pebble ACME acceptance.
  3. Local service runtime/API smoke.
  4. Browser smoke with agent-browser and helper proxy.
  5. Subagent review and final report.
- **Completion criteria:** AC-001 到 AC-007 全部满足。
- **Non-completion traps:** 只跑 cargo test 不跑 Docker acceptance；浏览器直接访问 `127.0.0.1` 却未处理 Host；unknown host 未验证 upstream 未被调用；review 未独立执行。
- **Open blockers:** 无。
