# ethlambda

<!-- hy-mt2-i18n:start -->
[English](./README.md) | **中文** | [日本語](./README_ja.md) | [Español](./README_es.md)
<!-- hy-mt2-i18n:end -->


用 Rust 编写的极简、快速且模块化的 Lean Ethereum 客户端实现。

🌐 访问我们的网站 [**ethlambda.xyz**](https://ethlambda.xyz)，了解更多关于该项目的信息。

## 入门指南

### 先决条件

- [Rust](https://rust-lang.org/tools/install)
- [Git](https://git-scm.com/install)
- [Docker](https://www.docker.com/get-started)
- [yq](https://github.com/mikefarah/yq#install)

### 构建与测试

我们以 `cargo` 作为构建系统，但更倾向于使用 `make` 作为处理常见任务的便捷封装工具。以下是一些常见的目标指令：

```sh
# 格式化所有代码
make fmt
# 检查代码并生成代码规范报告
make lint
# 运行所有测试
make test
# 构建标记为“ghcr.io/lambdaclass/ethlambda:local”的 Docker 镜像
make docker-build DOCKER_TAG=local
```

运行 `make help` 命令，或查看我们的 [`Makefile`](./Makefile) 以了解其他有用命令。

### 在开发网络中运行

要使用 [lean-quickstart](https://github.com/blockblaz/lean-quickstart) 运行包含多个客户端的本地开发网络：

```sh
# 此命令将克隆 lean-quickstart，构建 Docker 镜像，并启动本地开发网络
make run-devnet
```

这将生成新的 genesis 文件，并启动所有已配置的客户端，同时开启指标收集功能。
按 `Ctrl+C` 可停止所有节点。

> **注意：**在 Linux 系统上，更大的 UDP 接收缓冲区有助于提升 QUIC 的性能。如果出现关于缓冲区大小的警告，请增加内核限制值：
> ```sh
> sudo sysctl -w net.core.rmem_max=7340032
> sudo sysctl -w net.core.wmem_max=7340032
> ```
> 若希望设置值在重启后依然有效，请将其添加到 `/etc/sysctl.conf` 文件中。在 Docker 环境中运行时，可通过 `--sysctl net.core.rmem_max=7340032 --sysctl net.core.wmem_max=7340032` 参数传递该设置。

> **重要提示：** 当手动运行节点（即不使用 `make run-devnet` 命令）时，必须至少启动一个带有 `--is-aggregator` 参数的节点，这样才能对验证结果进行聚合并将其纳入区块中。若没有该参数，网络虽会生成区块，但永远无法完成最终确认。

对于自定义的开发网络配置，需先前往 `lean-quickstart/local-devnet/genesis/validator-config.yaml` 并编辑该文件，然后再运行上述命令。有关如何配置开发网络的更多详细信息，请参阅 `lean-quickstart` 的文档。

## 贡献方式

我们欢迎大家贡献力量！请阅读我们的[CONTRIBUTING.md](./CONTRIBUTING.md)，了解参与指南。

## 社区

- **Telegram**：[ethlambda group](https://t.me/ethlambda_client)，我们会在此发布每日更新；欢迎前来提问或交流与Lean相关的任何话题。  
- **X (Twitter)**：[@ethlambda_lean](https://twitter.com/ethlambda_lean)，会偶尔在此发布更新。  
- **每周社区通话**：每周五在[@class_lambda](https://x.com/class_lambda)上进行直播；通话链接会提前发布在Telegram上。  
- **生态系统协调**：`ethereum/pm`上的[PQ Interop calls](https://github.com/ethereum/pm/issues?q=is%3Aissue+%22PQ+Interop%22+in%3Atitle)用于讨论跨客户端的Lean Ethereum相关工作及相关更新；会议链接会发布在每个议题中。

## 设计理念

许多历史悠久的客户端会随着时间推移逐渐变得臃肿。这通常是由于需要为现有用户提供旧版功能支持，或是试图实现过于宏大的功能目标所导致的。其结果往往是系统结构复杂、难以维护且容易出现错误。

与之相反，我们的理念以简洁为核心。我们致力于编写最少的代码，注重清晰性，并在设计上秉持简约原则。我们认为这是打造既快速又稳健的客户端的最佳方式。通过遵循这些原则，我们能够快速迭代，并尽早探索下一代功能。

欲进一步了解我们的工程理念，请[阅读我们博客的这篇文章](https://blog.lambdaclass.com/lambdas-engineering-philosophy/)。

## 设计原则

- 确保在所有目标环境中都能轻松完成设置与运行。
- 实现垂直集成，尽量减少依赖项。
- 采用便于后续扩展的结构设计。
- 拥有简洁的类型系统，避免泛型在代码库中泛滥。
- 减少抽象层次，只有在确实必要时才进行抽象处理；重复编写两三次代码也是可以接受的。
- 相较于过早优化，更应重视代码的可读性与可维护性。
- 避免在代码库中过度使用并发机制，因为并发会增加复杂性，仅在绝对必要时才使用。

## 📚 参考资料与致谢

以下链接、仓库、公司及项目在本次仓库的开发过程中发挥了重要作用，我们从它们身上学到了很多，特此向它们表示感谢并致以敬意。

- [Ethereum](https://ethereum.org/en/)  
- [LeanEthereum](https://github.com/leanEthereum)  
- [Zeam](https://github.com/blockblaz/zeam)  
- [Lantern](https://github.com/Pier-Two/lantern)

如果我们遗漏了某位贡献者，请提交问题以便我们将您加入列表。我们始终努力注明所有灵感来源及所使用的代码，但由于团队规模较大，难免会出现疏漏，有人可能会忘记标注引用信息。

## 当前状态

客户端实现了Lean Ethereum共识客户端的各项核心功能：

- **网络功能** — libp2p 对等节点连接、STATUS 消息处理，以及用于区块和证明的 gossipsub 机制  
- **状态管理** — 初始状态生成、状态转换函数、区块处理  
- **分叉选择** — 基于证明的头部选择机制的 3SF-mini 分叉选择规则实现  
- **验证者职责** — 证明的生成与广播、区块构建

其他功能：

- 支持通过 [leanMetrics](docs/metrics.md) 进行监控与可观测性分析  
- 提供 [lean-quickstart](https://github.com/blockblaz/lean-quickstart) 集成，简化开发网络运行流程

### 容器发布版本

Docker 镜像会发布到 `ghcr.io/lambdaclass/ethlambda`，并带有以下标签：

| 标签 | 描述 |
|-----|-------------|
| `devnetX` | 对应特定开发网络的稳定镜像（例如 `devnet4`） |
| `latest` | 当前运行中的开发网络最新稳定镜像的别名 |
| `unstable` | 基于最新的主分支提交构建；经过测试后会升级为 `devnetX`/`latest` |
| `sha-XXXXXXX` | 特定提交 |

[`RELEASE.md`](./RELEASE.md) 中详细介绍了我们的发布流程以及如何为新镜像添加标签。

### pq-devnet-5

我们当前正在运行 `pq-devnet-5` 版本。该版本对应的 Docker 标签为 `devnet5`。

### pq-devnet-6

`pq-devnet-6` 目前仍处于规划阶段，尚未确定具体功能。可能的候选方向包括替换 [LMD-GHOST](docs/lmd_ghost.md) 和 [3SF-mini](docs/3sf_mini.md)，或是实现[执行层集成](https://github.com/lambdaclass/ethlambda/pull/367)。

### 较旧的 devnet 版本

每个开发网的 Docker 标签都会随之发布，格式为 `devnetX`（即 `devnet1`、`devnet2`、`devnet3`、`devnet4`）。

当下一个 devnet 版本发布后，对旧版 devnet 的支持将会停止。

## 即将推出的功能 / 发展路线图

我们撰写了一篇[博客文章](https://blog.lambdaclass.com/ethlambda-devnet-5-and-beyond/)，介绍了我们认为未来短期内应加入的功能。

我们计划在近期优先实现的部分功能如下：

- [优化区块构建](https://github.com/lambdaclass/ethlambda/issues/465)
- [利用状态差异值在数据库中存储状态](https://github.com/lambdaclass/ethlambda/issues/238)
- [构建Goldfish + RLMD GHOST + BFT原型——devnet-6](https://github.com/lambdaclass/ethlambda/pull/434)
- [与执行客户端集成](https://github.com/lambdaclass/ethlambda/pull/367)，尤其是[ethrex](https://github.com/lambdaclass/ethrex)——devnet-7
- 用我们正在移植到Rust语言的实验性[ethp2p](https://github.com/ethp2p/ethp2p)替换libp2p
- [添加客程序以及STF的零知识证明功能](https://github.com/lambdaclass/ethlambda/issues/156)
- 用具体编程语言重写STF以实现形式化验证

### 实验性功能

在 PR [#269](https://github.com/lambdaclass/ethlambda/pull/269) 中，我们使用 Lean4 对状态转换函数的部分内容进行了概念验证层面的形式化处理。
