## Introduction to EIP-4844 Dev Usage

- Transaction format.
- How to send blob transactions?
- Opcode and precompile.
- Blob explorer.
- How to query blob contents?

## Blob Transaction Format
Blob transaction is a new transaction type of [EIP-2718: Typed Transaction Envelope](https://eips.ethereum.org/EIPS/eip-2718). This format defines the transaction and its receipt as follows:

### Transaction Structure

- **TransactionType**: A unique identifier for the transaction type, set as `BLOB_TX_TYPE (0x3)` for blob transactions.

- **TransactionPayload**: The payload for a blob transaction is structured as: `rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list, max_fee_per_blob_gas, blob_versioned_hashes, y_parity, r, s])`.
    - `max_fee_per_blob_gas (uint256)`: The maximum blob gas fee the sender is willing to pay. The actual fee charged is the blob base fee of the block.
    - `blob_versioned_hashes`: An array of hashes that can be used to verify the integrity of the blob content. Each hash starts with a 0x01 byte (representing the version) followed by the last 31 bytes of the SHA256 hash of the KZG. This approach is designed for [EVM-compatibility and future-compatibility](https://notes.ethereum.org/@vbuterin/proto_danksharding_faq#Why-use-the-hash-of-the-KZG-instead-of-the-KZG-directly).

> **Note**: The `gas_limit` does not account for blob gas. The blob gas is calculated separately by `131072 (0x20000)` per blob.

### Transaction Receipt Structure

- **ReceiptPayload**: The receipt payload for a blob transaction is defined as: `rlp([status, cumulative_transaction_gas_used, logs_bloom, logs])`.

> **Note**: `cumulative_transaction_gas_used` only reflects the cumulative gas used for executing transactions, excluding blob gas.

## Send Blob Transactions

### Networking Form

In the networking layer of EIP-4844, blob transactions use a different format for sending. The protocol requires execution nodes to check the validity of blob transactions when they are propagating.

- **Protocol Snippet**:
    - During transaction gossip responses (`PooledTransactions`), The EIP-2718 `TransactionPayload` of the blob transaction is wrapped to become: `rlp([tx_payload_body, blobs, commitments, proofs])`.
    - The node MUST validate `tx_payload_body` and verify the wrapped data against it. [Geth Example](https://github.com/ethereum/go-ethereum/blob/93c541ad563124e81d125c7ebe78938175229b2e/core/txpool/validation.go#L133-L160). For how `VerifyBlobProof` works, see introductions of [KZG-commitment](https://dankradfeist.de/ethereum/2020/06/16/kate-polynomial-commitments.html) and [trusted setups](https://vitalik.eth.limo/general/2022/03/14/trustedsetup.html).

### Curl

#### eth_sendRawTransaction

Send blob transaction:

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

Get blob transaction (the standard EIP-2718 blob transaction `TransactionPayload` is used):

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

Get blob transaction receipt:

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

[Go code for generating curl commands](./blob-eth_sendRawTransaction-curl-generator/main.go): run with `go run main.go`.

[The script with the generated curl command](./blob-eth_sendRawTransaction-curl-generator/blob_eth_sendRawTransaction.sh): run with `./blob_eth_sendRawTransaction.sh`.

View transaction on [Etherscan](https://sepolia.etherscan.io/tx/0x50dc1e2ec14cafb5acac600debe7b8765c73cbb7105ea33121284c3538ffbbc6) and [Blobscan](https://sepolia.blobscan.com/tx/0x50dc1e2ec14cafb5acac600debe7b8765c73cbb7105ea33121284c3538ffbbc6).

> **Note**: An RPC provider URL is required, or you need to run a node to execute the above curl commands, and test it only in testnet to prevent fund loss.

#### eth_sendTransaction

Send blob transaction:

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

Get blob transaction (the standard EIP-2718 blob transaction `TransactionPayload` is used):

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

Get blob transaction receipt:

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

[Go code for generating curl commands](./blob-eth_sendTransaction-curl-generator/main.go): run with `go run main.go`.

[The script with the generated curl command](./blob-eth_sendTransaction-curl-generator/blob_eth_sendTransaction.sh): run with `./blob_eth_sendTransaction.sh`.

View transaction on [Etherscan](https://sepolia.etherscan.io/tx/0x158173e2e27938f0605232e32f5fd524506439b7555d027b273bb70d07a3c899) and [Blobscan](https://sepolia.blobscan.com/tx/0x158173e2e27938f0605232e32f5fd524506439b7555d027b273bb70d07a3c899).

> **Note**: Most RPC providers (such as Infura and Alchemy) do not offer `eth_sendTransaction`.

> **Note**: For self-hosting Geth node: Signature fields are ignored and Geth would use the unlocked account to sign the transaction.

### Go-SDK (Using `eth_sendRawTransaction`)

Construct Non-blob Fields (the same as EIP-1559 transactions):

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
	// Provide BlobHash here if the transaction is a contract call,
	// and the contract uses blobhash opcode internally.
}

gasLimitWithoutAccessList, err := ethClient.EstimateGas(context.Background(), msg)
if err != nil {
	log.Crit("failed to estimate gas", "err", err)
}

// Explicitly set a gas limit to prevent the "insufficient funds for gas * price + value" error.
// Because if msg.Gas remains unset, CreateAccessList defaults to using RPCGasCap(), which can be excessively high.
msg.Gas = gasLimitWithoutAccessList * 3
accessList, gasLimitWithAccessList, errStr, rpcErr := gethClient.CreateAccessList(context.Background(), msg)
if rpcErr != nil {
	log.Crit("CreateAccessList RPC error", "error", rpcErr)
}
if errStr != "" {
	log.Crit("CreateAccessList reported error", "error", errStr)
}

// Fine-tune accessList because the 'to' address is automatically included in the access list by the Ethereum protocol: https://github.com/ethereum/go-ethereum/blob/v1.13.13/core/state/statedb.go#L1322
// This function returns a recalculated gas estimation based on the adjusted access list.
accessList, gasLimitWithAccessList = finetuneAccessList(accessList, gasLimitWithAccessList, msg.To)

func finetuneAccessList(accessList *types.AccessList, gasLimitWithAccessList uint64, to *common.Address) (*types.AccessList, uint64) {
	if accessList == nil || to == nil {
		return accessList, gasLimitWithAccessList
	}

	var newAccessList types.AccessList
	for _, entry := range *accessList {
		if entry.Address == *to && len(entry.StorageKeys) <= 24 {
			// Based on: https://arxiv.org/pdf/2312.06574.pdf
			// We remove the address and respective storage keys as long as the number of storage keys <= 24.
			// This removal helps in preventing double-counting of the 'to' address in access list calculations.
			gasLimitWithAccessList -= 2400
			// Each storage key saves 100 gas units.
			gasLimitWithAccessList += uint64(100 * len(entry.StorageKeys))
		} else {
			// Otherwise, keep the entry in the new access list.
			newAccessList = append(newAccessList, entry)
		}
	}
	return &newAccessList, gasLimitWithAccessList
}
```

Construct Blob Fields:

```golang
// Estimate blobFeeCap of the pending block.
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

> **Note**: A blob transaction can have 0 to 6 blobs because the maximum blobs per block are `MAX_BLOB_GAS_PER_BLOCK` / `GAS_PER_BLOB` = 786432 / 131072 = 6.

> **Note**: Geth's transaction pool (a widely adopted execution client) will reject blob transactions with 0 blob, [returning `blobless blob transaction` error when validating a transaction before adding it to tx pool](https://github.com/ethereum/go-ethereum/blob/93c541ad563124e81d125c7ebe78938175229b2e/core/txpool/validation.go#L120-L122).

Sign and Send the Transaction:

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

[Full implementation](./blob-send-transaction-Go-SDK/main.go): run with `go run main.go`.

## Fee Estimation and Bumping

### Estimating the Fee for Blob Transactions

#### Blob Fee and Gas

Blob base fee has a deterministic calculation:

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

`MIN_BLOB_BASE_FEE` is 1 wei.

`excess_blob_gas` represents the "extra" accumulated gas used historically than `TARGET_BLOB_GAS_PER_BLOCK * Totel Number of Blocks`, but it's bounded at 0 (>= 0).

`BLOB_BASE_FEE_UPDATE_FRACTION` is 3338477, which controls the increasing ratio of blob base fee.

`fake_exponential` calculates `factor * e ** (numerator / denominator)` by [Taylor expansion](https://en.wikipedia.org/wiki/Taylor_series) deterministically (rounded down) to prevent consensus divergence due to different rules to simulating an exponential function.

> **Note**: The blob base fee is calculated based on an [exponential EIP-1559 mechanism](https://dankradfeist.de/ethereum/2022/03/16/exponential-eip1559.html), in which `excess_blob_gas` would increase the blob base fee to the expectation price of the market. In the meantime, the expected blobs per block would still be the targeted number of blobs per block, which is 3 for now.

Blob Gas: 131072 (0x20000) per blob, 1 per byte, but the minimum unit for adding gas is a blob.

### Gas Fees: Blob vs Calldata

#### Gas
- **Blob Storage**: approximately 1 gas per byte (because the field is `BLS_MODULUS`), with charges applied per blob unit.
- **Calldata**: 16 gas per non-zero byte, 4 gas per zero byte.

> **Note**: Fully utilize each blob to avoid paying for unused space.

#### Gas Price
- **Blob Transactions**: Cost calculated using a blob base fee.
- **EIP-1559 Transactions**: Cost determined by the EIP-1559 base fee plus a tip fee.

#### Size
- **Blob**: > 127KiB and < 128KiB per blob, because the field is `BLS_MODULUS`.
- **Calldata**: bounded by block's gas limit, also there is ([a famously seen 128KiB limit](https://github.com/ethereum/go-ethereum/blob/93c541ad563124e81d125c7ebe78938175229b2e/core/txpool/legacypool/legacypool.go#L54-L50)) per transaction bounded in execution clients.

#### Conclusion

[A multidimensional fee market](https://ethresear.ch/t/multidimensional-eip-1559/11651) based on supply/demand. Hard to determine which one is cheaper beforehand.

- **Some Intuitions**:
    - Calldata is used for many purposes: contract call, rollup DA, etc. → blob is cheaper!
    - Only a 32 bytes hash of blob commitment is available in the EVM, designed for rollup. → blob is cheaper!
    - Blob is a relatively scarce resource, currently aiming for 3 blobs per block, whereas each transaction can include a calldata field, accommodating hundreds of transactions per block. → if blob transactions become congested, calldata may even be cheaper!

- **Tools**:
    - An example of cost comparison in [Etherscan](https://etherscan.io/tx/0x534284534dbad33a0683668b953ddfa7def3d328c737e6165b24691c71cef891#blobs) and [Blobscan](https://blobscan.com/tx/0x534284534dbad33a0683668b953ddfa7def3d328c737e6165b24691c71cef891): Note that a zero byte in blob (not known whether it's a valid 0, or a dummy value) is considered a zero byte in calldata, thus the saving is over-estimated.

- **Other Possibilities**:
    - Using private transaction services (e.g., flashbots), which can directly pay tips to the builder.

### Prioritizing a Transaction

Just increasing the effective tip as EIP-1559 transactions: `min(exec tip, exec cap - base fee)`.

- [Geth](https://github.com/ethereum/go-ethereum/blob/93c541ad563124e81d125c7ebe78938175229b2e/miner/ordering.go#L62-L70) and [Nethermind](https://github.com/NethermindEth/nethermind/blob/bf658d8525d8b1b3007c49ddc38b12a061e033a2/src/Nethermind/Nethermind.Consensus/Comparers/GasPriceTxComparerHelper.cs#L11-L30) use priority fee when selecting transactions from transaction pool.
- Even for a more sophisticated MEV strategy (e.g., solving a multidimensional knapsack problem), bumping the effective tip also brings higher revenue to the block builder.

### Bumping Fees for Pending Transactions (Replacing a transaction with the same nonce)

Due to blob pool's constraints for minimum bumping ratio (e.g., [Geth](https://github.com/ethereum/go-ethereum/blob/93c541ad563124e81d125c7ebe78938175229b2e/core/txpool/blobpool/blobpool.go#L1145-L1150) and [Nethermind](https://github.com/NethermindEth/nethermind/blob/bf658d8525d8b1b3007c49ddc38b12a061e033a2/src/Nethermind/Nethermind.TxPool/Comparison/CompareReplacedBlobTx.cs#L30-L32)). One needs to bump the `exec tip`, `exec cap` and `blob cap` aggressively for at least 100% to replace a sent transaction, this defense is added to prevent DoS attack since the payload of a blob transaction is large.


```golang
const escalateMultiplier = 2

// Bumping gas fee.
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

> **Note**: The penalty for replacing a pending transaction is high, which normally occurs during blob transaction congestion. One can try resubmitting a transaction first to see if it has been evicted by blob pool, otherwise bumping the gas price.

> **Note**: An error message example: `replacement transaction underpriced: new tx gas fee cap 67186612857 <= 44791075238 queued + 100% replacement penalty`.

## Troubleshooting Based on Blob Pool Implementation

Transactions are propagated through the Ethereum network by gossip protocol and are temporarily stored in the transaction pool. Because blob transactions carry a large payload, major clients implement certain constraints in their transaction pools. Highlighting a few of these constraints can be key for troubleshooting, preventing blob transactions from being rejected or deprioritized (stuck). We use Geth and Nethermind as examples.

### Geth (many RPC providers are based on it):

- An address cannot both hold transactions in legacy pool and the blob pool: `address already reserved`.
- Requires a significant `exec tip`, `exec cap` and `blob cap` bump (100%) to replace a transaction: `replacement transaction underpriced`.
- A limit on the maximum number of pending blob transactions per account: `account limit exceeded: pooled 16 txs`.
- [Blob transaction eviction](https://github.com/ethereum/go-ethereum/blob/93c541ad563124e81d125c7ebe78938175229b2e/core/txpool/blobpool/evictheap.go#L94-L115) from blob pool relies on 3 fee minimums per account (`exec tip`, `exec cap` and `blob cap`).
- Limits the number of blobs in a transaction to a maximum of 6 (the maximum allowed in a block): `too many blobs in transaction: have 7, permitted 6`.
- Exclude non-blob transactions: `blobless blob transaction`.
- Nonce-gapped blob txs are disallowed: `nonce too high`.

> **Note**: [Geth's blob pool "handbook"](https://github.com/ethereum/go-ethereum/blob/93c541ad563124e81d125c7ebe78938175229b2e/core/txpool/blobpool/blobpool.go#L132-L293).

### Nethermind:

- Set flags explicitly to enable blob pool.
- An address cannot both hold transactions in legacy pool and the blob pool.
- A limit on the maximum number of pending blob transactions per account.
- Reject blob with `MaxPriorityFeePerGas` lower than 1 gwei.
- Nonce-gapped blob txs are disallowed.
- Reject replacing blob tx by tx with less blobs.

> **Note**: [Blob Pool Unit Tests](https://github.com/NethermindEth/nethermind/blob/bf658d8525d8b1b3007c49ddc38b12a061e033a2/src/Nethermind/Nethermind.TxPool.Test/TxPoolTests.Blobs.cs).

## New Opcode & Precompile

### BLOBHASH Opcode

EIP-4844 introduces the `BLOBHASH` opcode with a gas cost of 3. Contracts can use it to retrieve the hash of transaction blobs. It takes an `index` parameter that specifies the blob's `index`; if the `index` is out of bounds, it returns a zero bytes32 value. See [Geth Implementation](https://github.com/ethereum/go-ethereum/blob/93c541ad563124e81d125c7ebe78938175229b2e/core/vm/eips.go#L273-L283).

### Point Evaluation Precompile

A precompile at 0x0A that verifies a KZG proof which claims that a blob (represented by a commitment) evaluates to a given value at a given point. Each invocation costs 50000 gas.

**Demo code in EIP-4844**:

```python
def point_evaluation_precompile(input: Bytes) -> Bytes:
    """
    Verify p(z) = y given commitment that corresponds to the polynomial p(x) and a KZG proof.
    Also verify that the provided commitment matches the provided versioned_hash.
    """
    # The data is encoded as follows: versioned_hash | z | y | commitment | proof | with z and y being padded 32 byte big endian values
    assert len(input) == 192
    versioned_hash = input[:32]
    z = input[32:64]
    y = input[64:96]
    commitment = input[96:144]
    proof = input[144:192]

    # Verify commitment matches versioned_hash
    assert kzg_to_versioned_hash(commitment) == versioned_hash

    # Verify KZG proof with z and y in big endian format
    assert verify_kzg_proof(commitment, z, y, proof)

    # Return FIELD_ELEMENTS_PER_BLOB and BLS_MODULUS as padded 32 byte big endian values
    return Bytes(U256(FIELD_ELEMENTS_PER_BLOB).to_be_bytes32() + U256(BLS_MODULUS).to_be_bytes32())
```

[Geth Implementation](https://github.com/ethereum/go-ethereum/blob/93c541ad563124e81d125c7ebe78938175229b2e/core/vm/contracts.go#L1094-L1128).

### Examples

#### Call Point Evaluation Precompile Directly

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

// ... Construct other fields ...

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

[Full implementation](./invoke-EIP-4844-point-evaluation-precompile/main.go): run with `go run main.go`.

[A successful example (with valid calldata)](https://sepolia.etherscan.io/tx/0x021e5ee48c1eaa747ff4fd4bdffc5cd595d9fff7c2447a7aabca00fa1605f6fc): calldata + transfer (21000) + point evaluation precompile (50000).

[A failed example (without calldata)](https://sepolia.etherscan.io/tx/0x8236fa15da85272a47ed390491fafc28447db8af9057ccb3bd0c3ce2047559a7): failed, consuming all provided gas.

#### Call Point Evaluation Precompile within a Contract

**A Toy Contract**:
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

[Deployed Contract Address](https://sepolia.etherscan.io/address/0x45d38ded8a95656f72be2bd4de44f33e10eba1da): [the contract code is verified on Etherscan](https://sepolia.etherscan.io/address/0x45d38ded8a95656f72be2bd4de44f33e10eba1da#code).

[A Successful Example](https://sepolia.etherscan.io/tx/0xa207f9fa855e10149b328117b809fd13de96579ac9c1c06b7af810e6cc7c2d4b#eventlog).

[A Failed Example](https://sepolia.etherscan.io/tx/0xe0d210944193a52b7999532e6a91761dd2d0d71c4e5dcf9c06f09a65df4f7d45#eventlog): set the first byte in claim array to 0, the contract returns error with: `error verifying kzg proof: can’t verify opening proof` [Code Ref](https://github.com/ethereum/go-ethereum/blob/93c541ad563124e81d125c7ebe78938175229b2e/core/vm/contracts.go#L1123-L1125).

## Blob Explorers

- **Blobscan**: [Mainnet](https://blobscan.com) and [Sepolia](https://sepolia.blobscan.com).
    - **Block**: blob size, blob gas price, blob gas used, blob gas limit, blob as calldata gas, etc.
    - **Transaction**: total blob size, blob gas price, blob fee, blob gas used, blob as calldata gas used, blob as calldata gas fee, etc.
    - **Blob**: versioned hash, status, commitment, proof, size, blob data, etc.
    - **Stats Overview**:
        - **Block**: daily blocks, daily blob gas used, daily blob gas expenditure comparison (with calldata), daily blob fees, daily avg. blob fee, daily avg. blob gas price, etc.
        - **Transaction**: daily transactions, daily unique addresses, daily avg. max blob gas fee, etc.
        - **Blob**: daily blobs, daily blob size, etc.
    - **[Open-sourced](https://github.com/Blobscan)**: [supporting self-hosting deployment](https://docs.blobscan.com/docs/installation).

## Querying Blob Content

### One of the Motivations: Sync from DA

If all nodes are down, users can run a node on their own, syncing from DA to recover the chain's status, then withdraw their funds from L2 to L1.

### Consensus Node (Unpruned Blobs)

- Beacon API's [getBlobSidecars](https://ethereum.github.io/beacon-APIs/#/Beacon/getBlobSidecars):
  - [Lighthouse Example](./query-blob-content/lighthouse.txt).
  - [Prysm Example](./query-blob-content/prysm.txt).

- [List of Ethereum beacon chain RPC providers](https://docs.arbitrum.io/run-arbitrum-node/l1-ethereum-beacon-chain-rpc-providers#list-of-ethereum-beacon-chain-rpc-providers), some of them provide historical blob data.

### Blob Service Providers
- [Blobscan Example](./query-blob-content/blobscan.txt).
- [Blocknative Example](./query-blob-content/blocknative.txt).

> **Note**: After fetching the blob data, kzg commitment, and kzg proof, you can verify blob content (because blob hash is stored on-chain) locally and don't need to "trust" the service provider.

> **Note**: Other potential ways: [If data is deleted after 30 days, how would users access older blobs?](https://notes.ethereum.org/@vbuterin/proto_danksharding_faq#If-data-is-deleted-after-30-days-how-would-users-access-older-blobs).
