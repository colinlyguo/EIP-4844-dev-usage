## EIP-4844 开发使用介绍

- 交易格式。
- 如何发送 blob 交易？
- 操作码和预编译。
- Blob 浏览器。
- 如何查询 blob 内容？

## Blob 交易格式

Blob 交易是符合 [EIP-2718：类型交易封装](https://eips.ethereum.org/EIPS/eip-2718) 的一种新交易类型。该格式定义了交易及其收据如下：

### 交易结构

- **TransactionType**：交易类型的唯一标识符，对于 blob 交易，交易类型设置为`BLOB_TX_TYPE (0x3)`。

- **TransactionPayload**：blob 交易的有效载荷（payload）结构如下：`rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list, max_fee_per_blob_gas, blob_versioned_hashes, y_parity, r, s])`。
    - `max_fee_per_blob_gas (uint256)`：发送方愿意支付的最大 blob gas 费用。实际收取的费用是区块的 blob 基础费用。
    - `blob_versioned_hashes`：可用于验证 blob 内容完整性的哈希数组。每个哈希都以 0x01 字节开头（表示版本），后跟 KZG 的 SHA256 哈希的最后 31 个字节。此方法设计用于 [与 EVM 兼容和未来兼容性](https://notes.ethereum.org/@vbuterin/proto_danksharding_faq#Why-use-the-hash-of-the-KZG-instead-of-the-KZG-directly) 。

> **注意**：`gas_limit` 不包括 blob gas，blob gas 单独计算，每个 blob 为`131072 (0x20000)`。

### 交易收据结构

- **ReceiptPayload**：blob 交易的收据有效载荷定义为：`rlp([status, cumulative_transaction_gas_used, logs_bloom, logs])`。

> **注意**：`cumulative_transaction_gas_used` 仅反映执行交易所使用的累积 gas，不包括 blob gas。

## 发送 Blob 交易

### 网络形式

在 EIP-4844 的网络层中，blob 交易使用不同的格式进行发送。协议要求执行节点在传播时检查 blob 交易的有效性。

- **协议片段**：
    - 在交易 gossip 传播响应（`PooledTransactions`）期间，blob 交易的 EIP-2718 `TransactionPayload` 被包装为：`rlp([tx_payload_body, blobs, commitments, proofs])`。
    - 节点必须验证 `tx_payload_body` 并针对其验证包装数据。[Geth 示例](https://github.com/ethereum/go-ethereum/blob/93c541ad563124e81d125c7ebe78938175229b2e/core/txpool/validation.go#L133-L160) 。有关 `VerifyBlobProof` 的工作原理，请参阅 [KZG-commitment](https://dankradfeist.de/ethereum/2020/06/16/kate-polynomial-commitments.html) 和 [trusted setups](https://vitalik.eth.limo/general/2022/03/14/trustedsetup.html) 的介绍。

### Curl

#### eth_sendRawTransaction

发送 blob 交易：

```shell
curl --data '{
  "jsonrpc": "2.0",
  "method": "eth_sendRawTransaction",
  "params": ["0x03fa..."],
  "id": 1
}' \
-H "Content-Type: application/json" \
-X POST \
$RPC_PROVIDER_URL | jq
```

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "0x50dc1e2ec14cafb5acac600debe7b8765c73cbb7105ea33121284c3538ffbbc6"
}
```

获取 blob 交易（使用标准的 EIP-2718 blob 交易 `TransactionPayload`）：

```shell
curl --data '{
  "jsonrpc": "2.0",
  "method": "eth_getTransactionByHash",
  "params": [
    "0x50dc1e2ec14cafb5acac600debe7b8765c73cbb7105ea33121284c3538ffbbc6"
  ],
  "id": 1
}' \
-H "Content-Type: application/json" \
-X POST \
$RPC_PROVIDER_URL | jq
```

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "blockHash": "0xdd59ee9b848353ce4b30a907582d0e90f387e3622b34ca38dde796ab124cd5db",
    "blockNumber": "0x51c6d4",
    "from": "0xd932073c0350d17057b6da602356b2ae92648465",
    "gas": "0x6270",
    "gasPrice": "0x5da256f",
    "maxFeePerGas": "0x357dee4a",
    "maxPriorityFeePerGas": "0x14bb44",
    "maxFeePerBlobGas": "0x4d29c618fa",
    "hash": "0x50dc1e2ec14cafb5acac600debe7b8765c73cbb7105ea33121284c3538ffbbc6",
    "input": "0x",
    "nonce": "0x20",
    "to": "0xd932073c0350d17057b6da602356b2ae92648465",
    "transactionIndex": "0x7c",
    "value": "0x0",
    "type": "0x3",
    "accessList": [],
    "chainId": "0xaa36a7",
    "blobVersionedHashes": [
      "0x01ce755b14983c26efbad511bb2594f9aba54d199ffe762b507a1b5a9d4b3a61"
    ],
    "v": "0x1",
    "r": "0xeeec1c9f227c6886c9901c2a6792e88f694abae4cd1d9e19a0cb284a9b4e8567",
    "s": "0x5375e093b941ab9a25f53548b5b8728f6f2fb8de4822342a2d699fda362b6c4c",
    "yParity": "0x1"
  }
}
```

获取 blob 交易收据：

```shell
curl --data '{
  "jsonrpc": "2.0",
  "method": "eth_getTransactionReceipt",
  "params": [
    "0x50dc1e2ec14cafb5acac600debe7b8765c73cbb7105ea33121284c3538ffbbc6"
  ],
  "id": 1
}' \
-H "Content-Type: application/json" \
-X POST \
$RPC_PROVIDER_URL | jq
```

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "blobGasPrice": "0x80679abe1",
    "blobGasUsed": "0x20000",
    "blockHash": "0xdd59ee9b848353ce4b30a907582d0e90f387e3622b34ca38dde796ab124cd5db",
    "blockNumber": "0x51c6d4",
    "contractAddress": null,
    "cumulativeGasUsed": "0xae3bec",
    "effectiveGasPrice": "0x5da256f",
    "from": "0xd932073c0350d17057b6da602356b2ae92648465",
    "gasUsed": "0x5208",
    "logs": [],
    "logsBloom": "0x0000...",
    "status": "0x1",
    "to": "0xd932073c0350d17057b6da602356b2ae92648465",
    "transactionHash": "0x50dc1e2ec14cafb5acac600debe7b8765c73cbb7105ea33121284c3538ffbbc6",
    "transactionIndex": "0x7c",
    "type": "0x3"
  }
}
```

[用于生成 curl 命令的 Go 代码](./blob-eth_sendRawTransaction-curl-generator/main.go)：使用 `go run main.go` 运行。

[包含生成的 curl 命令的脚本](./blob-eth_sendRawTransaction-curl-generator/blob_eth_sendRawTransaction.sh)：使用 `./blob_eth_sendRawTransaction.sh` 运行。

在 [Etherscan](https://sepolia.etherscan.io/tx/0x50dc1e2ec14cafb5acac600debe7b8765c73cbb7105ea33121284c3538ffbbc6) 和 [Blobscan](https://sepolia.blobscan.com/tx/0x50dc1e2ec14cafb5acac600debe7b8765c73cbb7105ea33121284c3538ffbbc6) 上查看交易。

> **注意**：需要 RPC provider URL，或者需要运行节点来执行上述 curl 命令，并且仅在测试网中进行测试以防止资金损失。

#### eth_sendTransaction

发送 blob 交易：

```shell
curl --data '{
  "jsonrpc": "2.0",
  "method": "eth_sendTransaction",
  "params": [
    {
      "accessList": [],
      "blobVersionedHashes": [
        "0x01ce755b14983c26efbad511bb2594f9aba54d199ffe762b507a1b5a9d4b3a61"
      ],
      "blobs": [
        "0x0001..."
      ],
      "chainId": "0xaa36a7",
      "commitments": [
        "0x854288889c16ba728d66f58ef6f40a2e0041a89e0453b1af934bf45c8a0e26e48e35cb3abade84db8b39d65b85265e3f"
      ],
      "from": "0xd932073c0350d17057b6da602356b2ae92648465",
      "gas": "0x6270",
      "gasPrice": null,
      "hash": "0x23f2cbce16c8a144a653d9f919741143129d701f2cbe6cd7649b343ae6d0f0d3",
      "input": "0x",
      "maxFeePerBlobGas": "0x385d3c6730",
      "maxFeePerGas": "0xed46be3a46",
      "maxPriorityFeePerGas": "0x2540be400",
      "nonce": "0x29",
      "proofs": [
        "0xb54876f23a0bcf4d95d05bafd3091676562447b3a31ae1caaad208fb794a53aad24336fe0c636a882081aa57d220abb4"
      ],
      "r": "0x0",
      "s": "0x0",
      "to": "0xd932073c0350d17057b6da602356b2ae92648465",
      "type": "0x3",
      "v": "0x0",
      "value": "0x0",
      "yParity": "0x0"
    }
  ],
  "id": 1
}' \
-H "Content-Type: application/json" \
-X POST \
http://127.0.0.1:8545 | jq
```

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "0x158173e2e27938f0605232e32f5fd524506439b7555d027b273bb70d07a3c899"
}
```

获取 blob 交易（使用标准的 EIP-2718 blob 交易 `TransactionPayload`）：

```shell
curl --data '{
  "jsonrpc": "2.0",
  "method": "eth_getTransactionByHash",
  "params": [
    "0x158173e2e27938f0605232e32f5fd524506439b7555d027b273bb70d07a3c899"
  ],
  "id": 1
}' \
-H "Content-Type: application/json" \
-X POST \
$RPC_PROVIDER_URL | jq
```

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "blockHash": "0x2daaeca77155d06e64c130170cb1b2f53ed8e26c0e02fe24b7d0208ecd782488",
    "blockNumber": "0x51e294",
    "from": "0xd932073c0350d17057b6da602356b2ae92648465",
    "gas": "0x6270",
    "gasPrice": "0x1ab5ea2e27",
    "maxFeePerGas": "0xed46be3a46",
    "maxPriorityFeePerGas": "0x2540be400",
    "maxFeePerBlobGas": "0x385d3c6730",
    "hash": "0x158173e2e27938f0605232e32f5fd524506439b7555d027b273bb70d07a3c899",
    "input": "0x",
    "nonce": "0x29",
    "to": "0xd932073c0350d17057b6da602356b2ae92648465",
    "transactionIndex": "0x16",
    "value": "0x0",
    "type": "0x3",
    "accessList": [],
    "chainId": "0xaa36a7",
    "blobVersionedHashes": [
      "0x01ce755b14983c26efbad511bb2594f9aba54d199ffe762b507a1b5a9d4b3a61"
    ],
    "v": "0x0",
    "r": "0xd20ae6b93cee8467802601846df41bac73948553ce513e7cbe0e1998ff7e6fb9",
    "s": "0x5edcbd6ccd4462d0a33a747a5d9bf5653703566808b38007e3ce4532a1611348",
    "yParity": "0x0"
  }
}
```

获取 blob 交易收据：

```shell
curl --data '{
  "jsonrpc": "2.0",
  "method": "eth_getTransactionReceipt",
  "params": [
    "0x158173e2e27938f0605232e32f5fd524506439b7555d027b273bb70d07a3c899"
  ],
  "id": 1
}' \
-H "Content-Type: application/json" \
-X POST \
http://127.0.0.1:8545 | jq
```

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "blobGasPrice": "0x44831ac79",
    "blobGasUsed": "0x20000",
    "blockHash": "0x2daaeca77155d06e64c130170cb1b2f53ed8e26c0e02fe24b7d0208ecd782488",
    "blockNumber": "0x51e294",
    "contractAddress": null,
    "cumulativeGasUsed": "0xacdde",
    "effectiveGasPrice": "0x1ab5ea2e27",
    "from": "0xd932073c0350d17057b6da602356b2ae92648465",
    "gasUsed": "0x5208",
    "logs": [],
    "logsBloom": "0x0000...",
    "status": "0x1",
    "to": "0xd932073c0350d17057b6da602356b2ae92648465",
    "transactionHash": "0x158173e2e27938f0605232e32f5fd524506439b7555d027b273bb70d07a3c899",
    "transactionIndex": "0x16",
    "type": "0x3"
  }
}
```

[用于生成 curl 命令的 Go 代码](./blob-eth_sendTransaction-curl-generator/main.go)：使用 `go run main.go` 运行。

[包含生成的 curl 命令的脚本](./blob-eth_sendTransaction-curl-generator/blob_eth_sendTransaction.sh)：使用 `./blob_eth_sendTransaction.sh` 运行。

在 [Etherscan](https://sepolia.etherscan.io/tx/0x158173e2e27938f0605232e32f5fd524506439b7555d027b273bb70d07a3c899) 和 [Blobscan](https://sepolia.blobscan.com/tx/0x158173e2e27938f0605232e32f5fd524506439b7555d027b273bb70d07a3c899) 上查看交易。

> **注意**：大多数 RPC 提供程序（如 Infura 和 Alchemy）不提供 `eth_sendTransaction`。

> **注意**：对于自托管的 Geth 节点：签名字段将被忽略，并且 Geth 将使用未锁定的账户来签署交易。

### Go-SDK（使用 `eth_sendRawTransaction`）

构造非 blob 字段（与 EIP-1559 交易相同）：

```golang
privateKey, err := crypto.HexToECDSA(os.Getenv("PRIVATE_KEY"))
if err != nil {
	log.Crit("failed to create private key", "err", err)
}
publicKey := privateKey.Public()
publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
if !ok {
	log.Crit("failed to cast public key to ECDSA")
}
fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

rpcClient, err := rpc.Dial(os.Getenv("RPC_PROVIDER_URL"))
if err != nil {
	log.Crit("failed to connect to network", "err", err)
}

ethClient := ethclient.NewClient(rpcClient)
gethClient := gethclient.New(rpcClient)

chainID, err := ethClient.NetworkID(context.Background())
if err != nil {
	log.Crit("failed to get network ID", "err", err)
}

nonce, err := ethClient.PendingNonceAt(context.Background(), fromAddress)
if err != nil {
	log.Crit("failed to get pending nonce", "err", err)
}

gasTipCap, err := ethClient.SuggestGasTipCap(context.Background())
if err != nil {
	log.Crit("failed to get suggest gas tip cap", "err", err)
}

gasFeeCap, err := ethClient.SuggestGasPrice(context.Background())
if err != nil {
	log.Crit("failed to get suggest gas price", "err", err)
}

msg := ethereum.CallMsg{
	From:      fromAddress,
	To:        &fromAddress,
	GasFeeCap: gasFeeCap,
	GasTipCap: gasTipCap,
	// 这里提供 BlobHash 如果交易时合约调用，
	// 并且合约内使用 blobhash 操作码。
}

gasLimitWithoutAccessList, err := ethClient.EstimateGas(context.Background(), msg)
if err != nil {
	log.Crit("failed to estimate gas", "err", err)
}

// 明确设置 gas 限制，以防止出现 “gas * price + value 资金不足” 错误。
// 因为如果 msg.Gas 保持未设置，CreateAccessList 默认使用 RPCGasCap()，这可能会过高。
msg.Gas = gasLimitWithoutAccessList * 3
accessList, gasLimitWithAccessList, errStr, rpcErr := gethClient.CreateAccessList(context.Background(), msg)
if rpcErr != nil {
	log.Crit("CreateAccessList RPC error", "error", rpcErr)
}
if errStr != "" {
	log.Crit("CreateAccessList reported error", "error", errStr)
}

// 微调访问列表，因为 “to” 地址会被以太坊协议自动纳入访问列表：https://github.com/ethereum/go-ethereum/blob/v1.13.13/core/state/statedb.go#L1322
// 此函数根据调整后的访问列表返回重新计算的 gas 估算值。
accessList, gasLimitWithAccessList = finetuneAccessList(accessList, gasLimitWithAccessList, msg.To)

func finetuneAccessList(accessList *types.AccessList, gasLimitWithAccessList uint64, to *common.Address) (*types.AccessList, uint64) {
	if accessList == nil || to == nil {
		return accessList, gasLimitWithAccessList
	}

	var newAccessList types.AccessList
	for _, entry := range *accessList {
		if entry.Address == *to && len(entry.StorageKeys) <= 24 {
      // 基于：https://arxiv.org/pdf/2312.06574.pdf
      // 只要存储键的数量 <= 24，我们就会删除地址和相应的存储键。
      // 此删除有助于防止在访问列表计算中对 “to” 地址进行重复计算。
			gasLimitWithAccessList -= 2400
			// 每个存储密钥节省 100 gas。
			gasLimitWithAccessList += uint64(100 * len(entry.StorageKeys))
		} else {
			// 否则，将该条目保留在新的访问列表中。
			newAccessList = append(newAccessList, entry)
		}
	}
	return &newAccessList, gasLimitWithAccessList
}
```

构造 blob 字段：

```golang
// 估算待打包区块的 blobFeeCap  
parentHeader, err := client.HeaderByNumber(context.Background(), nil)
if err != nil {
	log.Crit("failed to get previous block header", "err", err)
}
parentExcessBlobGas := eip4844.CalcExcessBlobGas(*parentHeader.ExcessBlobGas, *parentHeader.BlobGasUsed)
blobFeeCap := eip4844.CalcBlobFee(parentExcessBlobGas)

blob := randBlob()
sideCar := makeSidecar([]kzg4844.Blob{blob})
blobHashes := sideCar.BlobHashes()

func makeSidecar(blobs []kzg4844.Blob) *types.BlobTxSidecar {
	var (
		commitments []kzg4844.Commitment
		proofs      []kzg4844.Proof
	)

	for _, blob := range blobs {
		c, _ := kzg4844.BlobToCommitment(blob)
		p, _ := kzg4844.ComputeBlobProof(blob, c)

		commitments = append(commitments, c)
		proofs = append(proofs, p)
	}

	return &types.BlobTxSidecar{
		Blobs:       blobs,
		Commitments: commitments,
		Proofs:      proofs,
	}
}
```

> **注意**：一个 blob 交易可以有 0 到 6 个 blob，因为每个区块的最大 blob 数量为 `MAX_BLOB_GAS_PER_BLOCK` / `GAS_PER_BLOB` = 786432 / 131072 = 6。

> **注意**：Geth 的交易池（一个广泛采用的执行客户端）将拒绝 0 blob 大小的 blob 交易，[在将交易添加到交易池之前验证时返回 `blobless blob transaction` 错误](https://github.com/ethereum/go-ethereum/blob/93c541ad563124e81d125c7ebe78938175229b2e/core/txpool/validation.go#L120-L122) 。

签名并发送交易：

```golang
blobTx := &types.BlobTx{
	ChainID:    uint256.MustFromBig(chainID),
	Nonce:      nonce,
	GasTipCap:  uint256.MustFromBig(gasTipCap),
	GasFeeCap:  uint256.MustFromBig(gasFeeCap),
	Gas:        gasLimitWithAccessList * 12 / 10,
	To:         fromAddress,
	BlobFeeCap: uint256.MustFromBig(blobFeeCap),
	BlobHashes: blobHashes,
	Sidecar:    sideCar,
}

if accessList != nil {
	blobTx.AccessList = *accessList
}

auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
if err != nil {
	log.Crit("failed to create transactor", "chainID", chainID, "err", err)
}

signedTx, err := auth.Signer(auth.From, types.NewTx(blobTx))
if err != nil {
	log.Crit("failed to sign the transaction", "err", err)
}

err = ethClient.SendTransaction(context.Background(), signedTx)
if err != nil {
	log.Crit("failed to send the transaction", "err", err)
}
```

[完整实现](./blob-send-transaction-Go-SDK/main.go)：使用 `go run main.go` 运行。

## 费用估算和提高

### 估算 Blob 交易的费用

#### Blob 费用和 Gas

Blob 基础费用具有确定性计算方法：

```python
def get_blob_base_fee(header: Header) -> int:
    return fake_exponential(
        MIN_BLOB_BASE_FEE,
        header.excess_blob_gas,
        BLOB_BASE_FEE_UPDATE_FRACTION
    )

def fake_exponential(factor: int, numerator: int, denominator: int) -> int:
    i = 1
    output = 0
    numerator_accum = factor * denominator
    while numerator_accum > 0:
        output += numerator_accum
        numerator_accum = (numerator_accum * numerator) // (denominator * i)
        i += 1
    return output // denominator
```

`MIN_BLOB_BASE_FEE` 为 1 wei。

`excess_blob_gas` 表示历史上比 `TARGET_BLOB_GAS_PER_BLOCK * Totel Number of Blocks` 多使用的“额外”累积的 gas，但它被限制为 0（>= 0）。

`BLOB_BASE_FEE_UPDATE_FRACTION` 为 3338477，它控制 blob 基础费用的增长比率。

`fake_exponential` 通过 [Taylor 展开](https://en.wikipedia.org/wiki/Taylor_series) 确定性地（向下取整）计算 `factor * e ** (numerator / denominator)`，以防止由于模拟指数函数的不同规则而导致共识分歧。

> **注意**：blob 基础费用是基于 [指数 EIP-1559 机制](https://dankradfeist.de/ethereum/2022/03/16/exponential-eip1559.html) 计算的，其中 `excess_blob_gas` 将使 blob 基础费用增加到市场的预期价格。与此同时，每个区块的预期 blob 数量仍将是每个区块的目标的 blob 数量，目前为 3。

Blob Gas：每个 blob 131072（0x20000）gas，每字节 1 gas，但增加 gas 的最小单位是一个 Blob。

### Gas 费用：Blob vs Calldata

#### Gas
- **Blob 存储**：每字节大约 1 gas（因为字段为 `BLS_MODULUS`），按 blob 为单位收费。
- **Calldata**：每个非零字节 16 gas，每个零字节 4 gas。

> **注意**：充分利用每个 Blob，避免支付未使用空间的费用。

#### Gas 价格
- **Blob 交易**：使用 blob 基础费用计算成本。
- **EIP-1559 交易**：成本由 EIP-1559 基础费用加上小费决定。

#### 大小
- **Blob**：每个 blob > 127KiB 并且 < 128KiB，因为字段为 `BLS_MODULUS`。
- **Calldata**：受区块的 gas limit 限制，此外每个交易受执行客户端中的限制（[一个著名的 128KiB 限制](https://github.com/ethereum/go-ethereum/blob/93c541ad563124e81d125c7ebe78938175229b2e/core/txpool/legacypool/legacypool.go#L54-L50)）。

#### 结论

基于供需的[多维费用市场](https://ethresear.ch/t/multidimensional-eip-1559/11651) 。难以事先确定哪个更便宜。

- **一些直觉**：
    - Calldata 用于许多目的：合约调用、Rollup DA 等。→ blob 更便宜！
    - 仅 blob 承诺的 32 字节哈希存在于 EVM 中，设计用于 Rollup。→ blob 更便宜！
    - Blob 相对稀缺，目前目标为每个区块 3 个 blob，而每个交易可以包含一个 calldata 字段，每个区块可容纳数百个交易。→ 如果 blob 交易拥挤，calldata 甚至可能更便宜！

- **工具**:
    - [Etherscan](https://etherscan.io/tx/0x534284534dbad33a0683668b953ddfa7def3d328c737e6165b24691c71cef891#blobs) 和 [Blobscan](https://blobscan.com/tx/0x534284534dbad33a0683668b953ddfa7def3d328c737e6165b24691c71cef891) 中的一个成本比较例子：请注意，blob 中的零字节（不知道它是有效的 0 还是未填充值）被视为 calldata 中的零字节，因此节省的费用被高估了。

- **其他可能性**：
    - 使用私人交易服务（例如 flashbots），可以直接向构建者支付小费。

### 优先处理交易

与 EIP-1559 交易一样，只需增加有效小费：`min(exec tip, exec cap - base fee)`。

- [Geth](https://github.com/ethereum/go-ethereum/blob/93c541ad563124e81d125c7ebe78938175229b2e/miner/ordering.go#L62-L70) 和 [Nethermind](https://github.com/NethermindEth/nethermind/blob/bf658d8525d8b1b3007c49ddc38b12a061e033a2/src/Nethermind/Nethermind.Consensus/Comparers/GasPriceTxComparerHelper.cs#L11-L30) 在从交易池中选择交易时使用优先小费。
- 即使对于更复杂的 MEV 策略（例如解决多维背包问题），增加有效小费也会给区块构建者带来更高的收入。

### 提高待处理交易的费用（替换具有相同 nonce 的交易）

由于 blob 交易池对最低提高比率有限制（例如 [Geth](https://github.com/ethereum/go-ethereum/blob/93c541ad563124e81d125c7ebe78938175229b2e/core/txpool/blobpool/blobpool.go#L1145-L1150) 和 [Nethermind](https://github.com/NethermindEth/nethermind/blob/bf658d8525d8b1b3007c49ddc38b12a061e033a2/src/Nethermind/Nethermind.TxPool/Comparison/CompareReplacedBlobTx.cs#L30-L32)），为了替换已发送的交易，需要至少将 `exec tip`、`exec cap` 和 `blob cap` 提高至少 100%，这种防御措施是为了防止 DoS 攻击，因为 blob 交易的有效负载很大。

```golang
const escalateMultiplier = 2

// 提高 gas fee。
gasTipCap = new(big.Int).Mul(gasTipCap, big.NewInt(escalateMultiplier))
gasFeeCap = new(big.Int).Mul(gasFeeCap, big.NewInt(escalateMultiplier))
blobFeeCap = new(big.Int).Mul(blobFeeCap, big.NewInt(escalateMultiplier))

tx := types.NewTx(&types.BlobTx{
	ChainID:    uint256.MustFromBig(chainID),
	Nonce:      nonce,
	GasTipCap:  uint256.MustFromBig(gasTipCap),
	GasFeeCap:  uint256.MustFromBig(gasFeeCap),
	Gas:        gasLimitWithAccessList * 12 / 10,
	To:         fromAddress,
	BlobFeeCap: uint256.MustFromBig(blobFeeCap),
	BlobHashes: blobHashes,
	Sidecar:    sideCar,
})

auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
if err != nil {
	log.Crit("failed to create transactor", "chainID", chainID, "err", err)
}

signedTx, err = auth.Signer(auth.From, tx)
if err != nil {
	log.Crit("failed to sign the transaction", "err", err)
}

err = ethClient.SendTransaction(context.Background(), signedTx)
if err != nil {
	log.Crit("failed to send the transaction", "err", err)
}
```

> **注意**：替换待处理交易的惩罚很高，通常发生在 blob 交易拥挤时。可以先尝试重新提交交易，看看是否已被 blob 交易池驱逐，否则提高 gas 价格。

> **注意**：错误消息示例：`replacement transaction underpriced: new tx gas fee cap 67186612857 <= 44791075238 queued + 100% replacement penalty`。

## 基于 Blob 交易池实现的故障排除

交易通过 gossip 协议在以太坊网络中传播，并临时存储在交易池中。由于 blob 交易携带大量有效负载，主要客户端在其交易池中实施了某些限制。强调这些限制中的一些对故障排除和防止 blob 交易被拒绝或优先级降低（卡住）可能至关重要。我们使用 Geth 和 Nethermind 作为示例。

### Geth（许多 RPC 提供者都是基于它的）：

- 一个地址不能同时在传统池和 blob 池中持有交易：`address already reserved`。
- 替换交易需要显著提高 `exec tip`、`exec cap` 和 `blob cap`（100%）：`replacement transaction underpriced`。
- 每个账户的最大待处理 blob 交易数量限制：`account limit exceeded: pooled 16 txs`。
- [Blob 交易驱逐](https://github.com/ethereum/go-ethereum/blob/93c541ad563124e81d125c7ebe78938175229b2e/core/txpool/blobpool/evictheap.go#L94-L115) 依赖于每个账户的 3 个最低费用（`exec tip`、`exec cap` 和 `blob cap`）。
- 限制每个交易中 blob 的数量最多为 6（区块中允许的最大数量）：`too many blobs in transaction: have 7, permitted 6`。
- 排除非 blob 交易：`blobless blob transaction`。
- 不允许nonce 间隔的 blob 交易：`nonce too high`。

> **参考**：[Geth 的 blob pool "手册"](https://github.com/ethereum/go-ethereum/blob/93c541ad563124e81d125c7ebe78938175229b2e/core/txpool/blobpool/blobpool.go#L132-L293)。

### Nethermind：

- 明确设置标志以启用 blob 池。
- 地址不能同时在传统池和 blob 池中持有交易。
- 每个账户待出处理的 blob 交易有最大数量限制。
- 拒绝 `MaxPriorityFeePerGas` 低于 1 gwei 的 blob。
- 不允许 nonce 间隔的 blob 交易。
- 拒绝用较少的 blob 替换 blob 交易。

> **参考**：[Blob Pool Unit Tests](https://github.com/NethermindEth/nethermind/blob/bf658d8525d8b1b3007c49ddc38b12a061e033a2/src/Nethermind/Nethermind.TxPool.Test/TxPoolTests.Blobs.cs)。

## 新的操作码和预编译

### BLOBHASH 操作码

EIP-4844 引入了 `BLOBHASH` 操作码，其 Gas成本为 3。合约可以使用它来检索交易 blob 的哈希。它接受一个 `index` 参数，指定 blob 的 `index`；如果 `index` 超出范围，则返回一个零的 bytes32 值。参见 [Geth 实现](https://github.com/ethereum/go-ethereum/blob/93c541ad563124e81d125c7ebe78938175229b2e/core/vm/eips.go#L273-L283)。

### 点评估（Point Evaluation）预编译

在 0x0A 处有一个预编译，用于验证 KZG 证明，该证明声称一个 blob（由承诺表示）在给定点上评估为给定值。每次调用消耗 50000 gas。

**EIP-4844 中的演示代码**：

```python
def point_evaluation_precompile(input: Bytes) -> Bytes:
    """
    给定与多项式 p(x) 相对应的承诺和 KZG 证明，验证 p(z) = y。
    还要验证所提供的承诺与所提供的版本控制哈希值（versioned_hash）是否匹配。 
    """
    #数据编码如下: versioned_hash | z | y | commitment | proof | with z and y being padded 32 byte big endian values
    assert len(input) == 192
    versioned_hash = input[:32]
    z = input[32:64]
    y = input[64:96]
    commitment = input[96:144]
    proof = input[144:192]

    # 验证承诺与 versioned_hash 是否匹配
    assert kzg_to_versioned_hash(commitment) == versioned_hash

    # 使用 z 和 y （大端格式） 验证 KZG 证明
    assert verify_kzg_proof(commitment, z, y, proof)

    #  返回 FIELD_ELEMENTS_PER_BLOB 和 BLS_MODULUS 扩展到 32 字节大端值
    return Bytes(U256(FIELD_ELEMENTS_PER_BLOB).to_be_bytes32() + U256(BLS_MODULUS).to_be_bytes32())
```

[Geth 实现](https://github.com/ethereum/go-ethereum/blob/93c541ad563124e81d125c7ebe78938175229b2e/core/vm/contracts.go#L1094-L1128)。

### 示例

#### 直接调用点评估预编译

```golang
pointEvaluationPrecompileAddress := common.HexToAddress("0x0A")
blob := randBlob()
sideCar := makeSidecar([]kzg4844.Blob{blob})
versionedHash := sideCar.BlobHashes()[0]
point := randFieldElement()
commitment := sideCar.Commitments[0]

proof, claim, err := kzg4844.ComputeProof(blob, point)
if err != nil {
	log.Crit("failed to create KZG proof at point", "err", err)
}

var calldata []byte
calldata = append(calldata, versionedHash.Bytes()...)
calldata = append(calldata, point[:]...)
calldata = append(calldata, claim[:]...)
calldata = append(calldata, commitment[:]...)
calldata = append(calldata, proof[:]...)

// ... 构造其他字段 ...

dynamicFeeTx := &types.DynamicFeeTx{
	ChainID:   chainID,
	Nonce:     nonce,
	GasTipCap: gasTipCap,
	GasFeeCap: gasFeeCap,
	Gas:       gasLimitWithAccessList,
	To:        &pointEvaluationPrecompileAddress,
	Value:     big.NewInt(0),
	Data:      calldata,
}

if accessList != nil {
	dynamicFeeTx.AccessList = *accessList
}

auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
if err != nil {
	log.Crit("failed to create transactor", "chainID", chainID, "err", err)
}

signedTx, err := auth.Signer(auth.From, types.NewTx(dynamicFeeTx))
if err != nil {
	log.Crit("failed to sign the transaction", "err", err)
}

err = ethClient.SendTransaction(context.Background(), signedTx)
if err != nil {
	log.Crit("failed to send transaction", "err", err)
}
```

[完整实现](./invoke-EIP-4844-point-evaluation-precompile/main.go)：使用 `go run main.go` 运行。

[成功的示例（具有有效的 calldata）](https://sepolia.etherscan.io/tx/0x021e5ee48c1eaa747ff4fd4bdffc5cd595d9fff7c2447a7aabca00fa1605f6fc)：calldata + 转账（21000）+ 点评估预编译（50000）。

[失败的示例（没有 calldata）](https://sepolia.etherscan.io/tx/0x8236fa15da85272a47ed390491fafc28447db8af9057ccb3bd0c3ce2047559a7)：失败，消耗了提供的所有 gas。

#### 在合约内调用点评估预编译

**一个玩具合约**：
```solidity
// SPDX-License-Identifier: MIT
// EVM VERSION: cancun
// Enable optimization: 2000000
pragma solidity ^0.8.24;

contract PointEvaluationPrecompileDemo {
    address private constant POINT_EVALUATION_PRECOMPILE_ADDRESS = 0x000000000000000000000000000000000000000A;
    uint256 private constant BLS_MODULUS = 52435875175126190479447740508185965837690552500527637822603658699938581184513;
    uint256 private constant HASH_OPCODE_BYTE = 0x49;

    event ProofVerificationSuccess(bytes32 indexed versionedHash, uint256 indexed point, bytes32 indexed claim);
    event ProofVerificationFailure(bytes32 indexed versionedHash, uint256 indexed point, bytes32 indexed claim);

    function verifyProofAndEmitEvent(
        bytes32 claim,
        bytes memory commitment,
        bytes memory proof
    ) external {
        require(commitment.length == 48, "Commitment must be 48 bytes");
        require(proof.length == 48, "Proof must be 48 bytes");

        bytes32 versionedHash = blobhash(0);

        // Compute random challenge point.
        uint256 point = uint256(keccak256(abi.encodePacked(versionedHash))) % BLS_MODULUS;

        bytes memory pointEvaluationCalldata = abi.encodePacked(
            versionedHash,
            point,
            claim,
            commitment,
            proof
        );

        (bool success,) = POINT_EVALUATION_PRECOMPILE_ADDRESS.staticcall(pointEvaluationCalldata);

        if (success) {
            emit ProofVerificationSuccess(versionedHash, point, claim);
        } else {
            emit ProofVerificationFailure(versionedHash, point, claim);
        }
    }
}
```

[部署的合约地址](https://sepolia.etherscan.io/address/0x45d38ded8a95656f72be2bd4de44f33e10eba1da)：[合约代码已在Etherscan上验证](https://sepolia.etherscan.io/address/0x45d38ded8a95656f72be2bd4de44f33e10eba1da#code)。

[成功的示例](https://sepolia.etherscan.io/tx/0xa207f9fa855e10149b328117b809fd13de96579ac9c1c06b7af810e6cc7c2d4b#eventlog)。

[失败的示例](https://sepolia.etherscan.io/tx/0xe0d210944193a52b7999532e6a91761dd2d0d71c4e5dcf9c06f09a65df4f7d45#eventlog)：将声明数组中的第一个字节设置为 0，合约返回错误：`error verifying kzg proof: can’t verify opening proof` [代码参考](https://github.com/ethereum/go-ethereum/blob/93c541ad563124e81d125c7ebe78938175229b2e/core/vm/contracts.go#L1123-L1125)。

## Blob 浏览器

- **Blobscan**：[主网](https://blobscan.com) 和 [Sepolia](https://sepolia.blobscan.com)。
  - **区块**：blob 大小、blob gas 价格、blob gas 使用量、blob gas 上限、blob 作为 calldata 的 gas 使用量等。
  - **交易**：总 blob 大小、blob gas 价格、blob 费用、blob gas 使用量、blob 作为 calldata 的 gas 使用量、blob 作为 calldata 的 gas 费用等。
  - **Blob**：版本化哈希、状态、承诺、证明、大小、blob 数据等。
  - **统计概览**：
    - **区块**：每日区块、每日 blob gas 使用量、每日 blob gas 支出对比（与 calldata）、每日 blob 费用、每日平均 blob 费用、每日平均 blob gas 价格等。
    - **交易**：每日交易、每日唯一地址、每日平均最大 blob gas 费用等。
    - **Blob**：每日 blob 数量、每日 blob 大小等。
  - **[开源](https://github.com/Blobscan)**：[支持自托管部署](https://docs.blobscan.com/docs/installation)。

## 查询 Blob 内容

### 动机之一：从 DA 同步

如果所有节点都宕机，用户可以在自己的计算机上运行一个节点，从 DA 同步以恢复链的状态，然后将他们的资金从 L2 提取到 L1。

### 共识节点（未修剪的 Blob）

- Beacon API 的 [getBlobSidecars](https://ethereum.github.io/beacon-APIs/#/Beacon/getBlobSidecars)：
  - [Lighthouse 示例](./query-blob-content/lighthouse.txt)
  - [Prysm 示例](./query-blob-content/prysm.txt)

- [以太坊信标链 RPC 提供商列表](https://docs.arbitrum.io/run-arbitrum-node/l1-ethereum-beacon-chain-rpc-providers#list-of-ethereum-beacon-chain-rpc-providers)，其中一些提供历史 blob 数据。

### Blob 服务提供商
- [Blobscan 示例](./query-blob-content/blobscan.txt)。
- [Blocknative 示例](./query-blob-content/blocknative.txt)。

> **注意**：获取 blob 数据、kzg 承诺和 kzg 证明后，你可以在本地验证 blob 内容（因为 blob 哈希存储在链上），无需“信任”服务提供商。

> **注意**：其他潜在的方式： [如果数据在 30 天后被删除，用户如何访问旧的 blob？](https://notes.ethereum.org/@vbuterin/proto_danksharding_faq#If-data-is-deleted-after-30-days-how-would-users-access-older-blobs)。
