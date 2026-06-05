# Darkflow (DF)
一个基于 [RustiFlow](https://github.com/idlab-discover/RustiFlow) 的暗网 ([Tor](https://spec.torproject.org/)) 流量特征高性能提取工具。

## 概述
基于 Rust 编程语言与 eBPF（Extended Berkeley Packet Filter）技术构建，在大规模网络流量处理场景下展现出卓越的处理性能与高吞吐能力。针对离线流量分析需求，系统还集成了高性能的 PCAP 文件解析模块，能够高效完成已采集网络流量数据的读取与处理。此外，系统提供多种预定义特征提取方案 (cic、cidds、nfstream、rustiflow)，并支持用户根据具体研究需求构建自定义特征集 (darkflow、lexnetflow)，从而满足不同网络分析任务的灵活性与可扩展性要求。

我们还提供了一个用于批量处理大规模数据集的脚本，能够自动遍历 PCAP/PCAPNG 流量文件并调用 `darkflow` 进行特征提取。在实现上，脚本基于 `ProcessPoolExecutor` 构建多进程并行处理机制，通过设置 worker 数量充分利用多核 CPU 资源，从而显著提升整体处理效率与吞吐能力，适用于大规模网络流量数据的特征工程与数据集构建任务。

## 核心特性
* **高吞吐量：** 利用 Rust 和 [Aya](https://aya-rs.dev/) 库进行 eBPF 程序的编译与执行，确保卓越性能和极高资源利用率。
* **通用的特征集：** 提供多种预定义特征集（流），并支持灵活创建满足特定需求的自定义特征集。
* **Pcap 离线支持：** 支持对 pcap 文件进行数据包分析，同时兼容 Linux 和 Windows 系统下生成的 pcap 文件。
* **多样化输出选项：** 特征数据可以输出到控制台和 CSV。

## 特征集
## 支持的数据包/报文头覆盖范围
目前支持从以下协议/报文头组合中提取流数据：

| 网络层 | 离线 pcap | 实时 eBPF |
| --- | --- | --- |
| 链路层 (Link) | Ethernet, Linux cooked capture, 802.1Q VLAN | Ethernet |
| 网络层 (Network) | IPv4, IPv6 | IPv4, IPv6 |
| IPv6 扩展 | 支持在传输层解析前处理扩展报文头 | 支持在传输层解析前处理扩展报文头 |
| 传输层 (Transport) | TCP, UDP, ICMP, ICMPv6 | TCP, UDP, ICMP, ICMPv6 |

说明：

* 实时（Realtime）模式仅支持 Linux 系统。
* 离线和实时模式旨在暴露相同的流语义，但时间戳和数据包长度的数据源可能会略有不同。
* 实时模式下的 VLAN 解析目前尚未实现。

## 系统架构
```txt
project/
├─ common/             # 共享数据结构
│  ├─ Cargo.toml
│  └─ src/lib.rs       # `EbpfEventIp*`
│
├─ darkflow/           # 用户空间加载器（loader）Crate
│  ├─ Cargo.toml
│  └─ src/main.rs      # 加载器代码
│  └─ ...
│
├─ ebpf-ipv4/          # 内核 eBPF Crate (IPv4)
│  ├─ Cargo.toml
│  └─ src/main.rs      # `#[no_std]` `#[no_main]` eBPF 程序
├─ ebpf-ipv6/          # 内核 eBPF Crate (IPv6)
│  ├─ Cargo.toml
│  └─ src/main.rs      # `#[no_std]` `#[no_main]` eBPF 程序
│
├─ xtask/              # 项目自动化 Crate
│  ├─ Cargo.toml
│  └─ src/main.rs      # 自定义任务 (eBPF 编译工作流)
│  └─ ...
```

### 实时处理架构
![Architecture Realtime](figures/realtime.png)

### 离线 PCAP 处理架构
![Architecture Offline](figures/offline.png)

## 使用方法
使用 `./setup.sh` 脚本安装依赖，并使用 `./build.sh` 脚本来构建 `darkflow` 二进制文件！将 `darkflow` 二进制文件复制到您自定义的路径，或放到 `/usr/local/bin` 文件夹中。
如果文件没有正确的执行权限，可以运行以下命令：

```bash
chmod +x /path/to/darkflow
```

### 使用 `gen_darkflow.py` 批量处理
我们提供了一个用于批量处理大规模数据集的脚本，能够自动遍历 PCAP/PCAPNG 流量文件并调用 `darkflow` 进行特征提取。在实现上，脚本基于 `ProcessPoolExecutor` 构建多进程并行处理机制，通过设置 worker 数量充分利用多核 CPU 资源，从而显著提升整体处理效率与吞吐能力，适用于大规模网络流量数据的特征工程与数据集构建任务。

```bash
nohup python gen_darkflow.py \
    --base-dir ./dataset_name \
    --feature-type darkflow \
    > gen_darkflow-dataset_name-darkflow.log 2>&1 &
```

### 使用 TUI 终端图形界面
如果您倾向于使用更直观的图形化界面，可以直接运行不带任何参数的 `darkflow` 命令来启动 TUI 界面。这会打开一个文本框，您可以在其中输入想要编辑的配置文件路径，或者选择新建配置。随后，将显示以下界面：

> **注意：** 当点击保存（save）按钮时，系统会提示您输入文件名。您可以在后续通过以下命令复用该文件：

```bash
darkflow --config-file <filename> realtime <interface> [--only-ingress]
```

```bash
# 例如 `./target/release/darkflow -c ./config.toml pcap ./t.pcap`
darkflow -c <filename> pcap <path to pcap file>
```

> 保存配置文件后，您可以安全地进行重置，这不会修改已保存的配置文件。

### 使用 Docker 容器
请确保您使用的是原生 Docker 环境，而非 Docker Desktop，且不要在机器上安装 Docker Desktop。如果在 Docker Desktop 环境下运行，该工具将无法按预期工作，因为 `--network host` 不会把容器连接到宿主机网络，而是连接到 Docker Desktop 所使用的虚拟机（VM）网络中。

* **构建容器**：
```bash
docker build -t darkflow .
```

* **运行容器**：
```bash
docker run --rm --network host -v /path/on/host:/app darkflow [ARGS]
```

如果需要实时捕获流量，请加上 `--privileged` 标志。
* **示例**：
```bash
docker run --rm --network host -v ./pcap:/app darkflow \
  -f basic \
  -o print \
  pcap /app/pcap.pcap

docker run --rm --privileged --network host -v ./output:/app darkflow \
  -f cic \
  -o csv \
  --export-path /app/output.csv \
  realtime enp0
```

说明：
* 当前版本的 CLI 使用类似 `-f basic` 和 `-o csv` 的位置标志（flags）；以往旧版本的位置参数示例已不再适用。
* 在容器中进行实时抓包依然依赖于宿主机 Linux 对 eBPF 和 `tc` 的支持，因此 `--privileged --network host` 仍是本地测试的实用基准配置。


## 开发指南
> 推荐直接使用 `./setup.sh` 脚本安装依赖，并使用 `./build.sh` 脚本来构建 `darkflow` 二进制文件！

### 前置条件
* **libpcap-dev**：
```sh
sudo apt install libpcap-dev
```

* **安装 Rust**：
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

* **Nightly 版本 Rust 工具链**：
```bash
rustup install stable
rustup toolchain install nightly --component rust-src
```

### 安装 bpf 链接器（bpf Linker）
* **对于 Linux x86_64 系统**：
```bash
cargo install bpf-linker
```

* **对于 MacOS/Linux (其他架构) 系统**：
```bash
brew install llvm
cargo install --no-default-features bpf-linker
```

* **针对 Ubuntu 20.04 LTS 的特定命令**：
```bash
sudo apt install linux-tools-5.8.0-63-generic
export PATH=/usr/lib/linux-tools/5.8.0-63-generic:$PATH
```

## 编译项目
* **eBPF 程序**：
```bash
cargo xtask ebpf-ipv4
cargo xtask ebpf-ipv6

# 或者编译 Release 版本
cargo xtask ebpf-ipv4 --release
cargo xtask ebpf-ipv6 --release
```

* **用户空间程序**：
```bash
cargo build
# 或者编译 Release 版本
cargo build --release
```

## 在开发模式下运行项目
```bash
cargo xtask run -- [OPTIONS] <COMMAND>
```

## 运行测试
```bash
cargo test
cargo test -- --fail-fast
cargo test --no-run
```
