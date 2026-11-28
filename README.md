# dhcp-relay-lease-consistency-validator

验证 DHCP relay、租约和跨网段地址一致性。

> **重要说明：本项目中所有 DHCP 报文（DISCOVER / REQUEST / OFFER / ACK / NAK）
> 均为模拟事件记录。校验器不发送、不接收任何真实网络流量，只对描述
> relay / 服务器观测结果的事件对象进行离线一致性分析。**

## 背景

当两个 DHCP relay 同时转发同一客户端请求，且 Option 82 记录了不同的接入
端口时，租约数据库中同一 MAC 可能出现两个地址，回程 DHCPOFFER 也可能被
送到错误网段。本工具针对这类场景做一致性校验。

## 功能

输入：

- 客户端 MAC、事务 ID（xid）、giaddr、Option 82（circuit-id / remote-id）
- relay 地址清单（relay 地址、giaddr、网段、期望的 circuit-id）
- 既有租约、地址池（网段、网关、地址范围、静态占用地址）
- 响应事件（OFFER / ACK / NAK 及其回程 giaddr）

对每次请求计算：

- 归属 relay（按 relay 地址 → giaddr → Option 82 circuit-id 依次解析）
- 可分配地址（续期复用原地址；请求地址被占用时重新分配；否则取池中
  第一个空闲地址）
- 最终租约（ACK 后写入租约数据库）

异常处理与检测：

- 重复请求（同 MAC + xid 重传复用首次分配结果）
- 同一请求被多个 relay 以不同 giaddr 转发（`multi_relay_forward`）
- 请求 / 响应 giaddr 与归属 relay 期望不一致（`wrong_giaddr` /
  `response_wrong_segment`，即 DHCPOFFER 可能被送到错误网段）
- 租约续期（REQUEST 复用并延长既有租约）
- 地址已被占用（静态占用或已租给其他 MAC）
- 同一 MAC 持有多个活动租约（`conflicting_leases`）
- 地址池耗尽、未知 relay、无匹配请求的响应

输出（`ValidationReport`）：

- `conflicting_leases`：冲突租约列表
- `wrong_giaddr`：giaddr 不一致事件列表
- `affected_segments`：受影响网段
- `recovery_steps`：恢复步骤（校正 relay 配置、释放冗余租约、保留 /
  回收占用地址、扩容地址池等）
- `lease_db`：校验后的租约数据库快照

## 使用示例

```python
from dhcp_relay_validator import (
    DHCPRelayConsistencyValidator, RelayAgent, AddressPool,
    RequestEvent, ResponseEvent, Option82, ACK,
)

relays = [
    RelayAgent("relay-1", "10.0.0.2", "10.0.0.1", "10.0.0.0/24",
               circuit_ids=("eth0/1",)),
    RelayAgent("relay-2", "10.1.0.2", "10.1.0.1", "10.1.0.0/24",
               circuit_ids=("eth1/1",)),
]
pools = [
    AddressPool("10.0.0.0/24", "10.0.0.1", "10.0.0.100", "10.0.0.110"),
    AddressPool("10.1.0.0/24", "10.1.0.1", "10.1.0.100", "10.1.0.110"),
]
requests = [
    RequestEvent("aa:bb:cc:00:00:01", 1001, "10.0.0.1",
                 Option82("eth0/1", "relay-1"), "10.0.0.2", timestamp=1.0),
    # 同一请求被 relay-2 以不同 giaddr 重复转发：
    RequestEvent("aa:bb:cc:00:00:01", 1001, "10.1.0.1",
                 Option82("eth1/1", "relay-2"), "10.1.0.2", timestamp=1.5),
]
report = DHCPRelayConsistencyValidator(relays, pools).validate(requests, [])
print(report.affected_segments)   # ['10.1.0.0/24']
print(report.recovery_steps)      # 排查 relay 转发与 Option 82 配置 ...
```

## 运行测试

```bash
python -m unittest discover -s tests -v
```

## 环境要求

- Python 3.8.2+（仅使用标准库：`dataclasses`、`ipaddress`、`typing`）

## 项目结构

- `dhcp_relay_validator/models.py` — 模拟报文与配置的数据模型
- `dhcp_relay_validator/validator.py` — 一致性校验核心逻辑
- `tests/test_validator.py` — 单元测试（多 relay、Option 82 变化、
  租约竞争、重复请求、错误 giaddr、续期、地址占用）
