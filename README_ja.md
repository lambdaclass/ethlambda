# ethlambda

<!-- hy-mt2-i18n:start -->
[English](./README.md) | [中文](./README_zh-CN.md) | **日本語** | [Español](./README_es.md)
<!-- hy-mt2-i18n:end -->


Rustで記述された、シンプルで高速かつモジュール化されたLean Ethereumクライアントの実装です。

🌐 プロジェクトについてさらに詳しく知るには、[**ethlambda.xyz**](https://ethlambda.xyz) にあるウェブサイトをご覧ください。

## はじめに

### 前提条件

- [Rust](https://rust-lang.org/tools/install)
- [Git](https://git-scm.com/install)
- [Docker](https://www.docker.com/get-started)
- [yq](https://github.com/mikefarah/yq#install)

### ビルドとテスト

ビルドシステムとしては `cargo` を使用していますが、よくあるタスクを簡単に実行できるラッパーとして `make` を好んで利用しています。以下はいくつかの一般的なターゲットです：

```sh
# すべてのコードをフォーマットする
make fmt
# コードのチェックとリンティングを実行する
make lint
# すべてのテストを実行する
make test
# "ghcr.io/lambdaclass/ethlambda:local" というタグが付けられた Docker イメージをビルドする
make docker-build DOCKER_TAG=local
```

その他の便利なコマンドについては、`make help` を実行するか、当プロジェクトの [`Makefile`](./Makefile) をご覧ください。

### デヴネットでの実行

[lean-quickstart](https://github.com/blockblaz/lean-quickstart) を使用して複数のクライアントを持つローカル devnet を実行するには：

```sh
# lean-quickstart をクローンし、Docker イメージをビルドし、ローカルの devnet を起動します
make run-devnet
```

これにより新しいgenesisファイルが生成され、メトリクス機能が有効な状態で設定されたすべてのクライアントが起動します。
すべてのノードを停止するには`Ctrl+C`を押してください。

> **注:** Linux上では、QUICのパフォーマンスはより大きなUDP受信バッファによって向上します。バッファサイズに関する警告が表示された場合は、カーネルの制限値を増やしてください：
> ```sh
> sudo sysctl -w net.core.rmem_max=7340032
> sudo sysctl -w net.core.wmem_max=7340032
> ```
> 再起動後も設定を維持したい場合は、`/etc/sysctl.conf`に追加してください。Dockerを使用する場合は、`--sysctl net.core.rmem_max=7340032 --sysctl net.core.wmem_max=7340032`を指定してください。

> **重要:** `make run-devnet` の外部でノードを手動で実行する場合、証明値が集約されてブロックに含まれるためには、少なくとも1つのノードを `--is-aggregator` フラグを使って起動する必要があります。このフラグがないと、ネットワークはブロックを生成しますが決して完了しません。

カスタムなdevnet設定を使用する場合は、上記のコマンドを実行する前に `lean-quickstart/local-devnet/genesis/validator-config.yaml` にアクセスしてファイルを編集してください。devnetの設定方法に関する詳細は、`lean-quickstart`のドキュメントをご覧ください。

## 貢献するには

ご貢献を心より歓迎します！参加方法のガイドラインについては、[CONTRIBUTING.md](./CONTRIBUTING.md)をご覧ください。

## コミュニティ

- **Telegram**: [ethlambda group](https://t.me/ethlambda_client)で毎日の更新情報を投稿しており、質問やLeanに関するあらゆる話題についてチャットできます。  
- **X (Twitter)**: 【@ethlambda_lean](https://twitter.com/ethlambda_lean)で時折更新情報を投稿しています。  
- **週次コミュニティ通話**: 毎週金曜日に[@class_lambda](https://x.com/class_lambda)でライブ配信され、通話のリンクは事前にTelegramに掲載されます。  
- **エコシステム連携**: `ethereum/pm`上の[PQ Interop calls](https://github.com/ethereum/pm/issues?q=is%3Aissue+%22PQ+Interop%22+in%3Atitle)では、クライアント間のLean Ethereumに関する作業や関連する更新情報が共有され、各イシューに会議のリンクが掲載されています。

## 哲学理念

長年にわたって使われてきた多くのクライアントは、時間が経つにつれて不要な機能が増えて肥大化してしまいます。これは、既存ユーザー向けの古い機能をサポートする必要があったり、過度に野心的なソフトウェアを実装しようとしたりすることが原因で起こります。その結果、複雑でメンテナンスが困難、かつエラーが発生しやすいシステムになってしまうことが多いのです。

それに対し、私たちのエンジニアリング哲学はシンプルさに根差しています。可能な限りコードを少なくし、明確性を最優先し、設計においてもシンプルさを重視するよう努めています。このアプローチこそが、高速で信頼性の高いクライアントを構築するための最良の方法だと考えています。これらの原則を守ることで、迅速に改善を重ね、次世代の機能を早期に試すことができるのです。

私たちのエンジニアリング哲学についてさらに詳しく知りたい方は、[ブログのこの記事](https://blog.lambdaclass.com/lambdas-engineering-philosophy/)をご覧ください。

## 設計原則

- すべてのターゲット環境で簡単にセットアップおよび実行できるようにする。
- 垂直統合されており、依存関係を最小限に抑える。
- 上に新たな機能を追加しやすい構造になっている。
- シンプルな型システムを持ち、コードベース全体にジェネリクスが乱立するのを避ける。
- 抽象化を少なくし、本当に必要な場合以外は一般化しない。コードを2、3回繰り返しても問題ない。
- 過度な最適化よりもコードの可読性と保守性を優先する。
- コードベース全体に並行処理が散在するのを避ける。並行処理は複雑さを増すため、厳密に必要な場合にのみ使用する。

## 📚 参考文献と謝辞

以下のリンク、リポジトリ、企業、プロジェクトは、このリポジトリの開発において重要な役割を果たしました。私たちは彼らから多くのことを学び、感謝の意を表したいと思います。

- [Ethereum](https://ethereum.org/en/)
- [LeanEthereum](https://github.com/leanEthereum)
- [Zeam](https://github.com/blockblaz/zeam)
- [Lantern](https://github.com/Pier-Two/lantern)

もし誰かを記載するのを忘れていた場合は、Issueを開いていただけると追加できます。私たちは常に参考にしたソースやコードへのリンクを記載するよう心がけていますが、複数人で構成される組織ですので間違いが生じることもあり、誰かがリファレンスの記載を忘れてしまうこともあるのです。

## 現在の状況

このクライアントは、Lean Ethereumコンセンサスクライアントの核心的な機能を実装しています：

- **ネットワーキング** — libp2pによるピア接続、STATUSメッセージの処理、ブロックおよびアテスタション用のgossipsub  
- **ステート管理** — ジェネシスステートの生成、ステート遷移関数、ブロックの処理  
- **フォーク選択** — アテスタションに基づくヘッド選択を伴う3SF-miniフォーク選択ルールの実装  
- **バリデータの役割** — アテスタションの生成とブロードキャスト、ブロックの構築

その他の機能：

- 監視および可観測性をサポートする [leanMetrics](docs/metrics.md)  
- デヴネットの運用を容易にするための [lean-quickstart](https://github.com/blockblaz/lean-quickstart) との連携

### コンテナのリリース情報

Dockerイメージは、以下のタグを付けて `ghcr.io/lambdaclass/ethlambda` に公開されています：

| Tag | 説明 |
|-----|-------------|
| `devnetX` | 特定デヴネット向けの安定版イメージ（例: `devnet4`） |
| `latest` | 現在実行中のデヴネットの最新安定版イメージの別名 |
| `unstable` | 最新のメインコミットからビルドされ、テストが完了すると `devnetX`/`latest` に昇格する |
| `sha-XXXXXXX` | 特定のコミット |

[`RELEASE.md`](./RELEASE.md)には、当プロジェクトのリリースプロセスや新しいDockerイメージにタグを付ける方法に関する詳細が記載されています。

### pq-devnet-5

現在は`pq-devnet-5`の仕様で動作しています。このバージョンにはDockerタグとして`devnet5`が利用可能です。

### pq-devnet-6

`pq-devnet-6`は現在計画段階にあり、まだ具体的な機能は定められていません。候補として考えられているのは、[LMD-GHOST](docs/lmd_ghost.md)および[3SF-mini](docs/3sf_mini.md)の置き換え、または[実行層との連携](https://github.com/lambdaclass/ethlambda/pull/367)です。

### 古いバージョンのdevnet

各devnetに対応するDockerタグが公開されており、その形式は`devnetX`（つまり`devnet1`、`devnet2`、`devnet3`、`devnet4`）です。

新しい devnet バージョンがリリースされると、以前の devnet リリースへのサポートは終了します。

## 将実装される機能／ロードマップ

近い将来実装すべき機能について、私たちは[ブログ記事](https://blog.lambdaclass.com/ethlambda-devnet-5-and-beyond/)を執筆しました。

近い将来実装を検討している機能の優先順位に従った一覧です：

- [ブロック構築の最適化](https://github.com/lambdaclass/ethlambda/issues/465)
- [データベース内の状態保存にstate-diffsの利用](https://github.com/lambdaclass/ethlambda/issues/238)
- [Goldfish + RLMD GHOST + BFTのプロトタイピング — devnet-6](https://github.com/lambdaclass/ethlambda/pull/434)
- [実行クライアントとの連携](https://github.com/lambdaclass/ethlambda/pull/367)、特に[ethrex](https://github.com/lambdaclass/ethrex) — devnet-7
- Rustへの移植を進めている実験的な[ethp2p](https://github.com/ethp2p/ethp2p)でlibp2pを置き換える
- [ゲストプログラムの追加およびSTFのZK証明](https://github.com/lambdaclass/ethlambda/issues/156)
- 形式的検証を可能にするため、具体論的プログラミング言語でSTFを書き直す

### 実験的な機能

PR [#269](https://github.com/lambdaclass/ethlambda/pull/269) において、Lean4を用いて状態遷移関数の一部を概念実証的に形式化したものがあります。
