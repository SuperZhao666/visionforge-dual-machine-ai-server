# ADR-008：SQLite 安全 schema 的 token 证明

**状态：Accepted**

`sqlite_master.sql` 的无害格式不应导致干净数据库启动失败；但删除安全约束必须被拒绝。
因此 schema 证明忽略空白和注释，只比较规范化 SQL token 序列。预建弱表仍 fail-closed，
不做静默修复。
