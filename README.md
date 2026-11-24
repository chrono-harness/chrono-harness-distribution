# chrono-harness-distribution

构建发布清单、生成安装器并验证安装。

使用 `cargo build --locked --manifest-path crates/distribution/Cargo.toml` 构建。运行 `mise trust` 后，`./check.sh` 按 Git 变更执行登记的检查。发行资产或启动器变更会选中资产身份、独立预期及启动器模型的 Verus 证明，以及依赖来源检查、原生构建和安装用例。

源码来自 [固定版本的原实现](https://github.com/ChronoAIProject/chrono-harness/tree/5f6892dfa2f73675a84e4ebdc3b06eb83b824d6e/crates/distribution)。

使用仓库的独立发行安装 `chrono-distribution`。下载对应平台的二进制和 `SHA256SUMS`，核对摘要后安装在工作树外。命令的 JSON 成果写入标准输出，诊断写入标准错误。

安装成功时，`install` 在 stdout 返回 `chrono-install-result/v1`，包含发行身份、平台和各工具的路径、长度、SHA-256。需要留存结果的调用方可将此次输出写入自己的持久存储。
