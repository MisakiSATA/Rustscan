# Rustscan

Rustscan 是一个用 Rust 编写的高性能网络扫描工具，支持 TCP/UDP 端口扫描、服务识别和操作系统检测。

## 功能特性

- 🚀 高性能异步批量扫描
- 🔍 支持 TCP 和 UDP 端口扫描
- 🎯 智能速率控制与批量并发
- 📊 实时进度显示
- 🔑 服务指纹识别
- 💻 操作系统检测
- 📝 支持 JSON 和 CSV 格式输出
- 🎨 彩色终端输出

## 安装

### 从源码安装

1. 确保已安装 Rust 工具链：

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

2. 克隆仓库并编译：

```bash
git clone https://github.com/yourusername/rustscan.git
cd rustscan
cargo build --release
```

3. 安装到系统：

```bash
cargo install --path .
```

## 使用方法

### 基本用法

```bash
rustscan -i <目标IP或网段> [选项]
```

### 选项说明

- `-i, --target`: 目标 IP 地址或网段（例如：192.168.1.1 或 192.168.1.0/24）
- `-s, --start-port`: 起始端口（默认：1）
- `-e, --end-port`: 结束端口（默认：65535）
- `-o, --timeout`: 超时时间（毫秒，默认：200）
- `-c, --threads`: 并发数（默认：1000）
- `-t, --scan-type`: 扫描类型（tcp/udp，默认：tcp）
- `-j, --json-output`: 输出 JSON 文件路径
- `-C, --csv-output`: 输出 CSV 文件路径
- `-p, --ping-only`: 仅进行存活检测

### 示例

1. 扫描单个 IP 的所有端口：

```bash
rustscan -i 192.168.1.1
```

2. 扫描网段并指定端口范围：

```bash
rustscan -i 192.168.1.0/24 -s 1 -e 1024
```

3. 使用高并发批量扫描：

```bash
rustscan -i 192.168.1.1 -c 5000
```

4. 保存结果到 JSON 文件：

```bash
rustscan -i 192.168.1.1 -j results.json
```

## 输出示例

```
[*] 开始TCP扫描 1 个目标...
[✓] 端口扫描: 65535/65535
[✓] 服务识别: 5/5
[✓] 操作系统识别: 1/1

存活主机:
  • 192.168.1.1
    - 22 (TCP) - SSH
    - 80 (TCP) - HTTP
    - 443 (TCP) - HTTPS
    - 3306 (TCP) - MySQL
    - 3389 (TCP) - RDP
```

## 性能优化

- 使用异步 I/O 和批量并发提升扫描效率
- 智能速率控制避免网络拥塞
- 批量处理端口和服务识别任务
- 预编译指纹正则表达式，提升识别速度
- 使用连接池复用资源

## 贡献指南

欢迎提交 Issue 和 Pull Request！在提交之前，请确保：

1. 代码符合 Rust 风格指南
2. 所有测试通过
3. 更新相关文档

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## 致谢

感谢所有贡献者和用户的支持！
