## Merkle Patricia Tree的Rust实现

本实现参考下列项目：

1. https://ethereum.github.io/yellowpaper/paper.pdf
2. https://github.com/ethereum/go-ethereum
3. https://github.com/zhangchiqing/merkle-patricia-trie

实现的功能：

- [x] Merkle Patricia Tree数据结构定义
- [x] Persistent Trie的插入（insert），查询（get）和回退（revert）
- [x] Merkle Proof构造与验证

注意，相比较于以太坊的官方实现（[脏标志](https://github.com/ethereum/go-ethereum/blob/2dfa4bcf6cb5263b8509722ffd14ddd02eddf47a/trie/node.go#L73)加[回写](https://github.com/ethereum/go-ethereum/blob/2dfa4bcf6cb5263b8509722ffd14ddd02eddf47a/trie/committer.go#L88)），本实现使用了一种更简单的方法实现数据的数据库持久化（直写），即当数据放入Trie中时，我们直接将其放入数据库，内存中仅保存merkle root。

### 平行宇宙中的形式化定义（误

我们首先给出Merkle Patricia Tree（以后称为Trie）的形式化定义，然后研究这样的定义背后的设计目的：

首先，Trie的作用其实并不是仅仅是提供键值对之间的映射，而是提供一个32 byte的序列$\mathtt{TRIE}(\mathfrak{J}) \in \mathbb{B}_{32}$或空序列$\emptyset$到一个键值对集合$\mathfrak{J}$的映射:

$$
\mathfrak{J} = \{(..., （I_0 \in \mathbb{B}, I_1 \in \mathbb{B}), ...\}
$$

其中$I_0$为一个键值对的键，$I_1$为一个键值对的值。

> 特别的，键$I_0$的表示形式为**4位**整型序列（nibbles），我们可以通过将原本键的每一个字节拆成高4位和低4位来得到这样的序列。

后面我们会看到，这些所有的键值对构成了一个类似radix tree的数据结构，我们定义这棵树的节点为$c(\mathfrak{J}, i)$，其中$i$表示对于一个键值对$(I_0, I_1)$，若$I_1$在该子树中，那么该子树中对应的键为$I_0[i..]$。不难看出，$c(\mathfrak{J}, 0)$代表整颗树的根。

该集合对应的32 bytes值表示为

$$
\mathtt{TRIE}(\mathfrak{J}) = \mathtt{KEC}(\mathtt{RLP}(c(\mathfrak{J}, 0)))
$$

其含义为：首先将该集合对应的radix tree的根节点使用RLP编码，然后使用Keccak256算法求哈希，得到的值便是该集合对应的32 byte键。该键被称为Trie的根哈希，得益于Keccak256哈希算法的抗碰撞性，我们可以认为一个根哈希可以决定唯一的一个Trie。

> Keccak256的有关资料参见[这里](https://en.wikipedia.org/wiki/SHA-3)
> 
> RLP（Recursive Length Prefix）编码是一种能将任意结构化数据编码为二进制表示的二进制编码，该编码在以太坊黄皮书的附录B中同样有形式化定义。笔者在该项目中使用了自己编写的RLP序列化和反序列化[serlp](https://github.com/M4tsuri/serlp)

接下来我们研究上面提到的radix tree节点$c(\mathfrak{J}, i)$的形式化定义：

首先定义一个键值对集合中键的最长共同前缀的长度表示为：

$$
p(\mathfrak{J}) = \max\{x: \exists \mathbf{pre}: ||\mathbf{pre}|| = x \land \forall I \in \mathfrak{J}: I_0[0..(x - 1)] = \mathbf{pre}\}
$$

那么$c(\mathfrak{J}, i)$的定义为：

$$
c(\mathfrak{J}, i) =
\begin{cases}
    (I_0[i..(||I_0|| - 1)], I_1), & \text{if } ||\mathfrak{J}|| = 1 \text{ where } \exists I: I \in \mathfrak{J} \\
    (I_0[i..(j - 1)], c(\mathfrak{J}, j)), & \text{if } i \ne j \text{ where } j = p(\mathfrak{J})\\
    (u(0), u(1), ..., u(15), v), & \text{otherwise } \text{ where } \\ &
    \quad u(j) \equiv c(\{I: I \in \mathfrak{J} \land I_0[i] = j\}, i + 1) \\ &
    \quad v = 
    \begin{cases}
        I_1, & \text{if } \exists I: I \in \mathfrak{J} \land ||I_0|| = i \\
        (), & \text{otherwise}
    \end{cases}

\end{cases}
$$

可以看到，这是一个递归定义，$\mathfrak{J}$表示当前层的子树中包含的键值对，其大小在递归的过程中递减。我们可以看到该式定义了三种类型的节点，我们通过一个例子进行解释：

假设有下面的键值对集合：

```
{
    (01e45a, 1),
    (01f45a, 2),
    (01058c, 3)
}
```

这些键值对构造出的radix tree如下：

可以看到，我们按照上述定义将这些键值对插入树中，然后求该树的根hash，便可以得到一个完整的Trie。对该Trie的任何修改操作都会导致根hash不吻合，我们因此便可以保证该数据结构的不可篡改性。

### 实际的形式化定义

看了上面的形式化定义，我们惊讶的发现所谓的Merkle Patricia Tree居然仅仅是一个radix tree加上了一个哈希。我们想象这样的一个场景：

我们知道，以太坊的世界状态是一个从账户地址到账户状态的映射，这些映射构成的键值对集合便存放在trie中，。我们在PC中运行了一个以太坊客户端，现在我们需要验证某个帐户的余额

**然而，不难发现如果以太坊真的采用的是这种数据结构，我们将完全无法在PC上运行一个节点！现在我们来结合以太坊对该数据结构的实际需求研究真正的形式化定义**
