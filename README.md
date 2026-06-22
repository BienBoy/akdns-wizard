# AKDNS Wizard

交互式 AKDNS 规则与 SmartDNS 配置生成工具。

`akdns-wizard.py` 会合并 `catalog.json` 和 `check.sh` 的平台清单，按问卷式流程检测流媒体解锁状态，再由用户决定哪些平台需要走 AKDNS 解锁。脚本只在最终确认保存时写入文件，中间状态保存在内存或临时目录。

## 功能

- 检测流媒体/服务解锁状态，检测平台来自 `catalog.json` 与 `check.sh` 的并集。
- 支持按服务实际区域选择检测范围，例如香港、台湾、澳门、日本、美国、韩国、全球/多区域，以及折叠分组。
- 根据检测结果辅助选择规则，但不会自动替用户决定分流策略。
- 规则设置页支持按状态、服务区域、backend 地区和关键词筛选。
- 批量策略支持对当前筛选、全部未解锁、剩余未选择等范围应用 backend。
- 生成 `akdns-rules.json` 和 `smartdns-akdns.conf`。
- SmartDNS 配置只把选中平台的域名分流到解锁 DNS，其他域名继续走公共 DNS。
- SmartDNS 负责实时优选 DNS 和 IP，脚本不做 DNS 跑分。
- 最终确认前不写入生成文件。

## 依赖

- Python 3.10+
- `bash`
- `curl`、`grep` 等 `check.sh` 运行所需的常见命令行工具
- 支持 curses 的终端可获得完整交互 UI

如果当前终端不支持 curses，脚本会退回简化文本问卷。

## 快速开始

```bash
python3 akdns-wizard.py
```

默认语言选择页停在中文。也可以指定界面语言：

```bash
python3 akdns-wizard.py --lang zh
python3 akdns-wizard.py --lang en
```

查看合并后的平台清单：

```bash
python3 akdns-wizard.py --list --lang zh
```

## 数据来源

脚本会优先从 URL 下载 `catalog.json` 和 `check.sh` 到临时目录；如果 URL 为空或下载失败且本地文件存在，则读取本地文件。

命令行参数：

```bash
python3 akdns-wizard.py --catalog-url "https://example.com/catalog.json" --check-url "https://example.com/check.sh"
```

环境变量：

```bash
AKDNS_CATALOG_URL="https://example.com/catalog.json"
AKDNS_CHECK_URL="https://example.com/check.sh"
```

当前默认 URL 指向远程 `catalog.json` 和 `check.sh`。如果 URL 为空，或下载失败且本地文件存在，则使用本地文件。

## 运行流程

1. 选择界面语言。
2. 选择流程：检测后生成、只测试解锁、只生成配置。
3. 选择公共 DNS：Cloudflare、Google、Quad9、AdGuard 或自定义。
4. 选择是否修改解锁 DNS。
5. 如需检测，选择检测地区和检测平台。
6. 查看检测结果，并在规则设置页选择需要 AKDNS 分流的平台。
7. 使用单个平台切换或批量策略选择 backend。
8. 最终确认，选择保存或退出不写入。

回退使用 `Ctrl+B`。退出使用 `q` 或 `Esc`。

## 规则策略

规则设置页中的检测结果只是建议。未解锁、部分可用、检测失败的平台会在批量策略中视为需要处理的范围，但是否启用 AKDNS 仍由用户确认。

批量策略支持：

- 对当前筛选中的未解锁/部分可用/检测失败平台应用策略。
- 对当前筛选中尚未选择的平台应用策略。
- 对当前筛选全部平台应用策略。
- 对已选择的平台重新设置 backend。
- 对全部未解锁/部分可用/检测失败平台应用策略。
- 清空指定范围内的选择。

backend 偏好是单选。选择“使用偏好 backend；平台不支持则跳过”时，不支持该 backend 的平台不会被选择。选择“使用偏好 backend；平台不支持则第一个可用”时，会退回该平台第一个可用 backend。

## 生成文件

默认文件名：

- `akdns-rules.json`
- `smartdns-akdns.conf`

最终确认页可以修改保存路径。不保存时不会写入这些文件。

`akdns-rules.json` 示例：

```json
{
  "rules": [
    {
      "service": "Netflix",
      "backend": "HK"
    }
  ]
}
```

`smartdns-akdns.conf` 会包含：

- 仅监听本机 loopback：`127.0.0.1:53` 和 `[::1]:53`。
- 公共 DNS 默认 upstream。
- `akdns-unlock` 解锁 DNS 分组。
- 公共 DNS fallback，只在 AKDNS upstream 不可用后回退。
- `speed-check-mode ping,tcp:80,tcp:443`。
- `dualstack-ip-selection yes`。
- `response-mode fastest-response`。
- 只针对选中平台域名的 `nameserver /domain/akdns-unlock` 分流规则。

## 常用参数

```text
--root ROOT                 指定包含 catalog.json 和 check.sh 的目录
--catalog-url URL           catalog.json 下载地址；为空或下载失败时使用本地文件
--check-url URL             check.sh 下载地址；为空或下载失败时使用本地文件
--lang zh|en                指定界面语言
--list                      列出合并后的平台清单
--version                   显示版本
```

## 环境变量

```text
AKDNS_CATALOG_URL           catalog.json 下载地址
AKDNS_CHECK_URL             check.sh 下载地址
AKDNS_TEST_WORKERS          解锁检测并发数
AKDNS_LANG                  默认界面语言，未指定 --lang 时使用
```

## 注意事项

- `catalog.json` 中的 backend 只表示可用于生成规则的解锁 backend，不用于判断平台实际服务区域。
- 不支持生成规则但 `check.sh` 支持检测的平台，会出现在检测结果中，但不会出现在可生成规则的平台列表里。
- `check.sh` 的检测结果依赖当前网络环境和运行平台，失败不一定代表服务永久不可用。
- SmartDNS 的实时优选由 SmartDNS 配置完成，脚本不会提前测速排序 DNS。
