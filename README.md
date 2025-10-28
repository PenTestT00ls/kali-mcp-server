# Kali MCP 项目

一个基于Kali Linux的MCP（Model Context Protocol）服务器项目，为AI助手提供渗透测试和安全评估工具接口。

## 项目概述

本项目包含两个主要组件：
- **kali_server.py** - Kali Linux API服务器，提供工具执行接口
- **mcp_server.py** - MCP协议服务器，连接AI助手与Kali工具
- **mcp.json** - MCP客户端配置文件

## 系统架构

```
AI助手 (MCP客户端) ←→ mcp_server.py ←→ kali_server.py ←→ Kali Linux工具
```

## 快速开始

### 环境要求

- Python 3.8+
- Kali Linux 系统（或安装了渗透测试工具的Linux系统）
- 网络连接（用于API通信）

### 安装步骤

1. **克隆项目**
   ```bash
   git clone <repository-url>
   cd kali-mcp-server
   ```

2. **安装依赖**
   ```bash
   pip install -r requirements.txt
   ```

3. **配置Kali服务器**
   - 确保Kali Linux系统已安装所需工具
   - 修改`kali_server.py`中的配置（如API端口）

4. **启动Kali API服务器**
   ```bash
   python kali_server.py
   ```
   服务器将在默认端口5000启动

5. **配置MCP客户端**
   - 修改`mcp.json`中的服务器地址
   - 确保Python路径正确

6. **启动MCP服务器**
   ```bash
   python mcp_server.py --server http://your-kali-ip:5000/
   ```

## 文件说明

### kali_server.py

Kali Linux API服务器，提供以下功能：

**主要特性：**
- 命令执行管理（支持超时控制）
- 多线程输出处理
- 错误处理和日志记录
- RESTful API接口

**API端点：**
- `POST /api/command` - 执行任意命令
- `POST /api/tools/nmap` - Nmap网络扫描
- `POST /api/tools/gobuster` - Gobuster目录扫描
- `POST /api/tools/dirb` - Dirb Web内容扫描
- `POST /api/tools/nikto` - Nikto Web服务器扫描
- `POST /api/tools/sqlmap` - SQLMap SQL注入检测
- `POST /api/tools/metasploit` - Metasploit模块执行
- `POST /api/tools/hydra` - Hydra密码破解
- `POST /api/tools/john` - John the Ripper密码破解
- `POST /api/tools/wpscan` - WPScan WordPress扫描
- `POST /api/tools/enum4linux` - Enum4linux枚举

### mcp_server.py

MCP协议服务器，提供以下工具函数：

**渗透测试工具：**
- `nmap_scan()` - 网络端口和服务发现
- `gobuster_scan()` - Web目录和文件发现
- `dirb_scan()` - Web内容扫描
- `nikto_scan()` - Web服务器漏洞扫描
- `sqlmap_scan()` - SQL注入检测
- `metasploit_run()` - Metasploit模块执行
- `hydra_attack()` - 密码暴力破解
- `john_crack()` - 密码哈希破解
- `wpscan_analyze()` - WordPress安全扫描
- `enum4linux_scan()` - Windows/Samba枚举

**信息收集工具：**
- `masscan_scan()` - 快速端口扫描
- `zmap_scan()` - 互联网范围扫描
- `unicornscan_scan()` - 异步网络扫描

### mcp.json

MCP客户端配置文件：

```json
{
  "mcpServers": {
    "kali_mcp": {
      "timeout": 180,
      "type": "stdio",
      "command": "python路径",
      "args": [
        "mcp_server.py路径",
        "--server",
        "Kali服务器地址"
      ]
    }
  }
}
```

## 工具功能详解

### 网络扫描工具

#### Nmap扫描
```python
nmap_scan(
    target="192.168.1.1",
    scan_type="-sV",
    ports="80,443,22",
    additional_args="-T4"
)
```

#### Masscan扫描
```python
masscan_scan(
    target="192.168.1.0/24",
    ports="1-1000",
    rate="1000"
)
```

### Web应用扫描工具

#### Gobuster目录扫描
```python
gobuster_scan(
    url="http://target.com",
    mode="dir",
    wordlist="/usr/share/wordlists/dirb/common.txt"
)
```

#### SQLMap SQL注入检测
```python
sqlmap_scan(
    url="http://target.com/login.php",
    data="username=admin&password=test",
    additional_args="--level=3 --risk=2"
)
```

### 密码攻击工具

#### Hydra暴力破解
```python
hydra_attack(
    target="192.168.1.1",
    service="ssh",
    username="admin",
    password="password123"
)
```

#### John the Ripper密码破解
```python
john_crack(
    hash_file="/path/to/hashes.txt",
    wordlist="/usr/share/wordlists/rockyou.txt"
)
```

## 📋 完整工具列表

### 🔍 网络扫描工具 (Network Scanners)
- **nmap** - 网络发现和安全扫描
- **masscan** - 大规模端口扫描
- **zmap** - 快速网络扫描
- **unicornscan** - 异步网络扫描
- **netdiscover** - 网络主机发现
- **naabu** - 快速端口扫描
- **rustscan** - Rust编写的快速端口扫描
- **netcat** - 网络工具瑞士军刀
- **traceroute** - 路由跟踪
- **tcpdump** - 网络包分析
- **wireshark** - 网络协议分析
- **socat** - 多用途中继工具

### 🌐 Web扫描工具 (Web Scanners)
- **gobuster** - 目录/文件暴力扫描
- **dirb** - Web内容扫描器
- **nikto** - Web服务器扫描器
- **wpscan** - WordPress安全扫描
- **whatweb** - Web技术识别
- **wafw00f** - WAF检测
- **dirsearch** - Web路径扫描
- **feroxbuster** - 快速内容发现
- **katana** - 下一代爬虫
- **meg** - 大规模URL获取
- **arjun** - 参数发现
- **paramspider** - 参数提取
- **waybackurls** - 历史URL获取
- **gau** - 获取已知URL
- **nuclei** - 漏洞扫描
- **vulmap** - 漏洞映射
- **joomscan** - Joomla扫描
- **droopescan** - Drupal扫描
- **cmsmap** - CMS扫描
- **wapiti** - Web应用漏洞扫描
- **arachni** - Web应用安全扫描
- **skipfish** - Web应用安全扫描
- **netsparker** - Web安全扫描
- **ffuf** - Web模糊测试
- **wfuzz** - Web应用模糊测试
- **xsser** - XSS漏洞扫描

### 🔎 枚举工具 (Enumeration Tools)
- **enum4linux** - SMB枚举
- **subfinder** - 子域名发现
- **amass** - 攻击面映射
- **dnsrecon** - DNS枚举
- **dnsenum** - DNS枚举
- **fierce** - DNS扫描
- **sublist3r** - 子域名枚举
- **findomain** - 子域名监控
- **whois** - 域名信息查询
- **autorecon** - 自动侦察
- **lazyrecon** - 懒人侦察
- **sn1per** - 渗透测试框架

### 🌐 Web爬虫 (Web Crawlers)
- **scrapy** - Python爬虫框架
- **gospider** - Go语言爬虫
- **linkfinder** - JavaScript端点发现
- **js_scan** - JavaScript扫描
- **secretfinder** - 密钥发现
- **hakrawler** - 快速爬虫
- **crawley** - Web爬虫
- **photon** - 极速爬虫
- **cewl** - 自定义词表生成

### 🛡️ 漏洞扫描 (Vulnerability Scanners)
- **openvas** - 开源漏洞评估
- **nmap_nse** - Nmap脚本引擎
- **vulners** - 漏洞数据库
- **vulmap** - 漏洞映射

### 🔒 安全评估 (Security Assessment)
- **lynis** - 安全审计工具
- **chkrootkit** - Rootkit检测
- **rkhunter** - Rootkit猎人
- **clamav** - 反病毒扫描

### 🔑 密码攻击 (Password Attackers)
- **hydra** - 在线密码破解
- **john** - 离线密码破解
- **hashcat** - 高级密码恢复
- **medusa** - 并行登录暴力破解
- **patator** - 多协议暴力破解
- **crowbar** - 暴力破解工具
- **crunch** - 密码生成器
- **johnny** - John the Ripper GUI
- **hash_identifier** - 哈希类型识别
- **wordlists** - 词表管理工具

### 📡 无线工具 (Wireless Tools)
- **aircrack** - WEP/WPA破解套件
- **reaver** - WPS攻击工具
- **wifite** - 自动化无线攻击
- **wifiphisher** - 无线钓鱼攻击

### 🎭 社会工程 (Social Engineering)
- **beef** - 浏览器利用框架
- **empire** - 后渗透框架
- **set** - 社会工程工具包
- **gophish** - 开源钓鱼框架

### 💻 后渗透 (Post Exploitation)
- **mimikatz** - Windows凭证提取
- **powersploit** - PowerShell攻击框架
- **psexec** - 远程执行工具
- **winexe** - Windows远程执行

### 🔧 逆向工程 (Reverse Engineering)
- **ghidra** - 软件逆向工程
- **ollydbg** - Windows调试器
- **gdb** - GNU调试器

### 💥 漏洞利用框架 (Exploit Frameworks)
- **metasploit** - 渗透测试框架
- **exploitdb** - 漏洞利用数据库

### 📱 移动安全 (Mobile Security)
- **mobsf** - 移动安全框架
- **apktool** - Android应用工具

### ☁️ 云安全 (Cloud Security)
- **pacu** - AWS渗透测试
- **scout_suite** - 云环境安全审计
- **cloudsploit** - 云安全配置扫描

### 🔌 IoT安全 (IoT Security)
- **firmwalker** - 固件分析工具
- **iotseeker** - IoT设备扫描

### 📊 报告工具 (Reporting Tools)
- **dradis** - 协作报告框架
- **serpico** - 渗透测试报告
- **faraday** - 协作渗透测试
- **magictree** - 渗透测试数据管理
- **pipal** - 密码分析工具
- **consolidated_report** - 综合报告工具

## 📊 统计信息
- **总工具数量**: 91个工具
- **分类数量**: 16个类别

所有工具都已集成到MCP服务器中，可以通过相应的API端点进行调用。

## 配置说明

### Kali服务器配置

在`kali_server.py`中可配置：
- `API_PORT` - API服务端口（默认：5000）
- `DEBUG_MODE` - 调试模式开关
- `COMMAND_TIMEOUT` - 命令执行超时时间（秒）

### MCP服务器配置

在`mcp_server.py`中可配置：
- `DEFAULT_KALI_SERVER` - 默认Kali服务器地址
- `DEFAULT_REQUEST_TIMEOUT` - API请求超时时间

## 安全注意事项

⚠️ **重要安全警告**

1. **授权测试**：仅在获得明确授权的情况下使用本工具
2. **法律合规**：确保所有测试活动符合当地法律法规
3. **网络隔离**：建议在隔离的测试环境中使用
4. **日志记录**：所有操作都会被记录，确保可追溯性
5. **数据保护**：妥善处理测试过程中获取的敏感信息

## 故障排除

### 常见问题

1. **连接失败**
   - 检查Kali服务器是否正常运行
   - 验证网络连接和防火墙设置
   - 确认API端口未被占用

2. **工具未找到**
   - 确保Kali Linux已安装所需工具
   - 检查工具路径配置
   - 验证工具执行权限

3. **权限错误**
   - 确保以适当权限运行脚本
   - 检查文件系统权限
   - 验证网络访问权限

### 日志查看

所有操作日志可在控制台查看，或通过配置日志文件进行记录。

## 扩展开发

### 添加新工具

1. 在`kali_server.py`中添加新的API端点
2. 在`mcp_server.py`中注册对应的MCP工具函数
3. 更新配置文件

### 自定义配置

支持通过环境变量和配置文件进行自定义配置。

## 许可证

本项目基于开源许可证发布，具体许可证信息请查看LICENSE文件。

## 贡献指南

欢迎提交Issue和Pull Request来改进本项目。

**免责声明**：本工具仅供安全研究和授权测试使用，使用者需对自身行为承担全部法律责任。

