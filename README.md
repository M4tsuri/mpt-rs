## Merkle Patricia Tree的Rust实现

**博客文章：https://dere.press/2022/01/24/eth-trie/**

本实现参考下列项目：

1. https://ethereum.github.io/yellowpaper/paper.pdf
2. https://github.com/ethereum/go-ethereum
3. https://github.com/zhangchiqing/merkle-patricia-trie

实现的功能：

- [x] Merkle Patricia Tree数据结构定义
- [x] Persistent Trie的插入（insert），查询（get）和回退（revert）
- [x] Merkle Proof构造与验证
- [x] 数据持久化

注意，相比较于以太坊的官方实现的节点粒度的[脏标志](https://github.com/ethereum/go-ethereum/blob/2dfa4bcf6cb5263b8509722ffd14ddd02eddf47a/trie/node.go#L73)，本实现的脏标志粒度为整棵树，这会带来潜在的性能问题，可我太懒了。

### 食用方式

```
git clone https://github.com/M4tsuri/mpt-rs
cd mpt-rs && cargo test
```

### 文档

```
cargo doc --open
```
