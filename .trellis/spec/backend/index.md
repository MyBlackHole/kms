# Backend Development Guidelines

> Best practices for backend development in this project.

---

## Overview

This directory contains guidelines for backend development. Fill in each file with your project's specific conventions.

---

## Guidelines Index

| Guide | Description | Status |
|-------|-------------|--------|
| [API Token 动态认证](./auth-api-tokens.md) | Token 动态管理规范，静态+动态双重认证 | ✅ Filled |
| [加密模块规范](./crypto-guidelines.md) | 算法引擎实现、EnvelopeEncryption 路由、KEK 适配、测试要求 | ✅ Filled |
| [KMIP API 协议](./kmip-api.md) | JSON-KMIP 调度器、认证桥接、自定义扩展框架、类型系统 | ✅ Filled |
| [CLI → KMIP 桥](./cli-kmip.md) | CLI 客户端 KMIP JSON 请求构建、认证流程、命令→操作映射 | ✅ Filled |
| [Directory Structure](./directory-structure.md) | Module organization and file layout | ✅ Filled |
| [Database Guidelines](./database-guidelines.md) | ORM patterns, queries, migrations | To fill |
| [Error Handling](./error-handling.md) | Error types, handling strategies | To fill |
| [Quality Guidelines](./quality-guidelines.md) | Code standards, forbidden patterns, clippy rules, security checklist | ✅ Filled |
| [Logging Guidelines](./logging-guidelines.md) | Structured logging, log levels | To fill |

---

## How to Fill These Guidelines

For each guideline file:

1. Document your project's **actual conventions** (not ideals)
2. Include **code examples** from your codebase
3. List **forbidden patterns** and why
4. Add **common mistakes** your team has made

The goal is to help AI assistants and new team members understand how YOUR project works.

---

**Language**: All documentation should be written in **English**.
