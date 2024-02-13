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
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/log"
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

	// Estimate pending block's blobFeeCap.
	parentHeader, err := client.HeaderByNumber(context.Background(), nil)
	if err != nil {
		log.Crit("failed to get previous block header", "err", err)
	}
	parentExcessBlobGas := eip4844.CalcExcessBlobGas(*parentHeader.ExcessBlobGas, *parentHeader.BlobGasUsed)
	blobFeeCap := eip4844.CalcBlobFee(parentExcessBlobGas)

	log.Info("blob gas info", "excessBlobGas", parentExcessBlobGas, "blobFeeCap", blobFeeCap)

	blob := randBlob()
	sideCar := makeSidecar([]kzg4844.Blob{blob})
	blobHashes := sideCar.BlobHashes()

	tx := types.NewTx(&types.BlobTx{
		ChainID:    uint256.MustFromBig(chainID),
		Nonce:      nonce,
		GasTipCap:  uint256.MustFromBig(gasTipCap),
		GasFeeCap:  uint256.MustFromBig(gasFeeCap),
		Gas:        gasLimit * 12 / 10,
		To:         fromAddress,
		BlobFeeCap: uint256.MustFromBig(blobFeeCap),
		BlobHashes: blobHashes,
		Sidecar:    sideCar,
	})

	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
	if err != nil {
		log.Crit("failed to create transactor", "chainID", chainID, "err", err)
	}

	signedTx, err := auth.Signer(auth.From, tx)
	if err != nil {
		log.Crit("failed to sign the transaction", "err", err)
	}

	err = client.SendTransaction(context.Background(), signedTx)
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
		"blobFeeCap", signedTx.BlobGasFeeCap(),
		"blobHashes", signedTx.BlobHashes())

	log.Info("Waiting for transaction to be mined...")

	escalateBlockNumber := uint64(4)
	submitBlockNumber := (*parentHeader).Number.Uint64()
	var receipt *types.Receipt
	for {
		time.Sleep(15 * time.Second)

		_, isPending, err := client.TransactionByHash(context.Background(), signedTx.Hash())
		if err != nil || isPending {
			log.Warn("failed to get transaction by hash or the tx is still pending", "hash", signedTx.Hash().String(), "err", err, "isPending", isPending)

			currentBlockNumber, err := client.BlockNumber(context.Background())
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
					Gas:        gasLimit * 12 / 10,
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

				err = client.SendTransaction(context.Background(), signedTx)
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

		receipt, err = client.TransactionReceipt(context.Background(), signedTx.Hash())
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
