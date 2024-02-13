package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/log"
	"github.com/holiman/uint256"
	"github.com/joho/godotenv"
)

const escalateMultiplier = 10

func main() {
	glogger := log.NewGlogHandler(log.NewTerminalHandler(os.Stderr, true))
	glogger.Verbosity(log.LevelInfo)
	log.SetDefault(log.NewLogger(glogger))

	err := godotenv.Load("../.env")
	if err != nil {
		log.Crit("failed to load .env file", "err", err)
	}

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

	client, err := ethclient.Dial(os.Getenv("RPC_PROVIDER_URL"))
	if err != nil {
		log.Crit("failed to connect to network", "err", err)
	}

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Crit("failed to get network ID", "err", err)
	}

	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Crit("failed to get pending nonce", "err", err)
	}

	gasTipCap, err := client.SuggestGasTipCap(context.Background())
	if err != nil {
		log.Crit("failed to get suggest gas tip cap", "err", err)
	}

	gasFeeCap, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Crit("failed to get suggest gas price", "err", err)
	}

	gasLimit, err := client.EstimateGas(context.Background(),
		ethereum.CallMsg{
			From:      fromAddress,
			To:        &fromAddress,
			GasFeeCap: gasFeeCap,
			GasTipCap: gasTipCap,
			Value:     big.NewInt(0),
		})
	if err != nil {
		log.Crit("failed to estimate gas", "err", err)
	}

	parentHeader, err := client.HeaderByNumber(context.Background(), nil)
	if err != nil {
		log.Crit("failed to get previous block header", "err", err)
	}
	parentExcessBlobGas := eip4844.CalcExcessBlobGas(*parentHeader.ExcessBlobGas, *parentHeader.BlobGasUsed)
	blobFeeCap := eip4844.CalcBlobFee(parentExcessBlobGas)

	log.Info("blob gas info", "excessBlobGas", parentExcessBlobGas, "blobFeeCap", blobFeeCap)

	gasTipCap = new(big.Int).Mul(gasTipCap, new(big.Int).SetUint64(escalateMultiplier))
	gasFeeCap = new(big.Int).Mul(gasFeeCap, new(big.Int).SetUint64(escalateMultiplier))
	blobFeeCap = new(big.Int).Mul(blobFeeCap, new(big.Int).SetUint64(escalateMultiplier))

	blob := randBlob()
	sideCar := makeSidecar([]kzg4844.Blob{blob})
	tx := types.NewTx(&types.BlobTx{
		ChainID:    uint256.MustFromBig(chainID),
		Nonce:      nonce,
		GasTipCap:  uint256.MustFromBig(gasTipCap),
		GasFeeCap:  uint256.MustFromBig(gasFeeCap),
		Gas:        gasLimit * 12 / 10,
		To:         fromAddress,
		BlobFeeCap: uint256.MustFromBig(blobFeeCap),
		BlobHashes: sideCar.BlobHashes(),
		Sidecar:    sideCar,
	})

	txData, err := json.Marshal(tx)
	if err != nil {
		log.Crit("failed to JSON marshal transaction", "err", err)
		return
	}

	var txMap map[string]interface{}
	err = json.Unmarshal(txData, &txMap)
	if err != nil {
		log.Crit("failed to JSON unmarshal transaction data", "err", err)
		return
	}

	txMap["from"] = fromAddress
	txData, err = json.Marshal(txMap)
	if err != nil {
		log.Crit("failed to JSON marshal transaction with new field", "err", err)
		return
	}

	curlCmd := fmt.Sprintf("curl --data '{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendTransaction\",\"params\":[%s],\"id\":1}' -H \"Content-Type: application/json\" -X POST http://127.0.0.1:8545 | jq\n", txData)

	scriptContent := fmt.Sprintf("#!/bin/bash\n\n%s", curlCmd)

	err = os.WriteFile("blob_eth_sendTransaction.sh", []byte(scriptContent), 0755)
	if err != nil {
		log.Crit("failed to write curl command to file", "err", err)
		return
	}

	log.Info("Curl command has been written to file blob_eth_sendTransaction.sh")
}

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

func randBlob() kzg4844.Blob {
	var blob kzg4844.Blob
	for i := 0; i < len(blob); i += gokzg4844.SerializedScalarSize {
		fieldElementBytes := randFieldElement()
		copy(blob[i:i+gokzg4844.SerializedScalarSize], fieldElementBytes[:])
	}
	return blob
}

func randFieldElement() [32]byte {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		panic("failed to get random field element")
	}
	var r fr.Element
	r.SetBytes(bytes)

	return gokzg4844.SerializeScalar(r)
}
