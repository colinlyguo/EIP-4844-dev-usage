package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/ethclient/gethclient"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/holiman/uint256"
	"github.com/joho/godotenv"
)

const escalateMultiplier = 2

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

	// Estimate pending block's blobFeeCap.
	parentHeader, err := ethClient.HeaderByNumber(context.Background(), nil)
	if err != nil {
		log.Crit("failed to get previous block header", "err", err)
	}
	parentExcessBlobGas := eip4844.CalcExcessBlobGas(*parentHeader.ExcessBlobGas, *parentHeader.BlobGasUsed)
	blobFeeCap := eip4844.CalcBlobFee(parentExcessBlobGas)

	log.Info("blob gas info", "excessBlobGas", parentExcessBlobGas, "blobFeeCap", blobFeeCap)

	blob := randBlob()
	sideCar := makeSidecar([]kzg4844.Blob{blob})
	blobHashes := sideCar.BlobHashes()

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

	log.Info("transaction parameters",
		"hash", signedTx.Hash().String(),
		"chainID", signedTx.ChainId(),
		"nonce", signedTx.Nonce(),
		"gasTipCap", signedTx.GasTipCap(),
		"gasFeeCap", signedTx.GasFeeCap(),
		"gasLimit", signedTx.Gas(),
		"to", signedTx.To(),
		"accessList", signedTx.AccessList(),
		"data", signedTx.Data(),
		"blobFeeCap", signedTx.BlobGasFeeCap(),
		"blobHashes", signedTx.BlobHashes())

	log.Info("Waiting for transaction to be mined...")

	escalateBlockNumber := uint64(4)
	submitBlockNumber := (*parentHeader).Number.Uint64()
	var receipt *types.Receipt
	for {
		time.Sleep(15 * time.Second)

		_, isPending, err := ethClient.TransactionByHash(context.Background(), signedTx.Hash())
		if err != nil || isPending {
			log.Warn("failed to get transaction by hash or the tx is still pending", "hash", signedTx.Hash().String(), "err", err, "isPending", isPending)

			currentBlockNumber, err := ethClient.BlockNumber(context.Background())
			if err != nil {
				log.Crit("failed to get current block number", "err", err)
			}

			if currentBlockNumber >= submitBlockNumber+escalateBlockNumber {
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

				log.Info("escalating gas prices and resending transaction",
					"hash", signedTx.Hash().String(),
					"chainID", signedTx.ChainId(),
					"nonce", signedTx.Nonce(),
					"gasTipCap", signedTx.GasTipCap(),
					"gasFeeCap", signedTx.GasFeeCap(),
					"gasLimit", signedTx.Gas(),
					"to", signedTx.To(),
					"blobFeeCap", signedTx.BlobGasFeeCap(),
					"blobHashes", signedTx.BlobHashes())

				submitBlockNumber = currentBlockNumber
			}

			continue
		}

		receipt, err = ethClient.TransactionReceipt(context.Background(), signedTx.Hash())
		if err != nil {
			log.Crit("failed to get transaction receipt", "err", err)
		}
		break
	}

	if receipt.Status == types.ReceiptStatusSuccessful {
		log.Info("Transaction mined successfully with status 1 in block", "blockNumber", receipt.BlockNumber.Uint64())
	} else {
		log.Info("Transaction failed with status 0 in block", "blockNumber", receipt.BlockNumber.Uint64())
	}
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
