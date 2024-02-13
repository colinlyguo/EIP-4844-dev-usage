package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/log"
	"github.com/joho/godotenv"
)

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

	gasLimit, err := client.EstimateGas(context.Background(), ethereum.CallMsg{
		From:      fromAddress,
		To:        &pointEvaluationPrecompileAddress,
		GasFeeCap: gasFeeCap,
		GasTipCap: gasTipCap,
		Value:     big.NewInt(0),
		Data:      calldata,
	})
	if err != nil {
		log.Crit("failed to estimate gas", "err", err)
	}

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasTipCap: gasTipCap,
		GasFeeCap: gasFeeCap,
		Gas:       gasLimit,
		To:        &pointEvaluationPrecompileAddress,
		Value:     big.NewInt(0),
		Data:      calldata,
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
		log.Crit("failed to send transaction", "err", err)
	}

	log.Info("transaction sent", "txHash", signedTx.Hash().Hex())
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
