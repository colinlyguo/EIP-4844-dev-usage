package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	gokzg4844 "github.com/crate-crypto/go-kzg-4844"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
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

	blsModulo, ok := new(big.Int).SetString("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10)
	if !ok {
		log.Crit("failed to initialize bls_modulo")
	}

	demoContractAddress := common.HexToAddress("0x45d38deD8a95656f72be2bD4de44F33E10EBA1da")

	blob := randBlob()
	sideCar := makeSidecar([]kzg4844.Blob{blob})
	versionedHash := sideCar.BlobHashes()[0]

	pointHash := crypto.Keccak256Hash(versionedHash.Bytes())
	pointBigInt := new(big.Int).SetBytes(pointHash.Bytes())
	point := kzg4844.Point(new(big.Int).Mod(pointBigInt, blsModulo).Bytes())

	commitment := sideCar.Commitments[0]

	proof, claim, err := kzg4844.ComputeProof(blob, point)
	if err != nil {
		log.Crit("failed to create KZG proof at point", "err", err)
	}

	var mockRunCalldata []byte
	mockRunCalldata = append(mockRunCalldata, versionedHash.Bytes()...)
	mockRunCalldata = append(mockRunCalldata, point[:]...)
	mockRunCalldata = append(mockRunCalldata, claim[:]...)
	mockRunCalldata = append(mockRunCalldata, commitment[:]...)
	mockRunCalldata = append(mockRunCalldata, proof[:]...)

	// Verify proof locally: the same implementation as the precompile.
	if err := mockRun(mockRunCalldata); err != nil {
		log.Crit("failed to verify KZG proof at point", "err", err)
	}

	abiFile, err := os.ReadFile("./abi.json")
	if err != nil {
		log.Crit("Unable to read ABI file", "err", err)
	}

	var demoContractABI abi.ABI
	err = json.Unmarshal(abiFile, &demoContractABI)
	if err != nil {
		log.Crit("Unable to parse ABI", "err", err)
	}

	var claimArray [32]byte

	copy(claimArray[:], claim[:])
	calldata, err := demoContractABI.Pack(
		"verifyProofAndEmitEvent",
		claimArray,
		commitment[:],
		proof[:],
	)
	if err != nil {
		log.Crit("failed to pack calldata", "err", err)
	}

	// Estimate pending block's blobFeeCap.
	parentHeader, err := ethClient.HeaderByNumber(context.Background(), nil)
	if err != nil {
		log.Crit("failed to get previous block header", "err", err)
	}
	parentExcessBlobGas := eip4844.CalcExcessBlobGas(*parentHeader.ExcessBlobGas, *parentHeader.BlobGasUsed)
	blobFeeCap := eip4844.CalcBlobFee(parentExcessBlobGas)

	log.Info("blob gas info", "excessBlobGas", parentExcessBlobGas, "blobFeeCap", blobFeeCap)

	gasTipCap = new(big.Int).Mul(gasTipCap, big.NewInt(escalateMultiplier))
	gasFeeCap = new(big.Int).Mul(gasFeeCap, big.NewInt(escalateMultiplier))
	blobFeeCap = new(big.Int).Mul(blobFeeCap, big.NewInt(escalateMultiplier))

	msg := ethereum.CallMsg{
		From:          fromAddress,
		To:            &demoContractAddress,
		GasFeeCap:     gasFeeCap,
		GasTipCap:     gasTipCap,
		BlobGasFeeCap: blobFeeCap,
		BlobHashes:    sideCar.BlobHashes(),
		Data:          calldata,
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

	blobTx := &types.BlobTx{
		ChainID:    uint256.MustFromBig(chainID),
		Nonce:      nonce,
		GasTipCap:  uint256.MustFromBig(gasTipCap),
		GasFeeCap:  uint256.MustFromBig(gasFeeCap),
		Gas:        gasLimitWithAccessList,
		To:         demoContractAddress,
		BlobFeeCap: uint256.MustFromBig(blobFeeCap),
		BlobHashes: sideCar.BlobHashes(),
		Sidecar:    sideCar,
		Data:       calldata,
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

const (
	blobVerifyInputLength           = 192  // Max input length for the point evaluation precompile.
	blobCommitmentVersionKZG  uint8 = 0x01 // Version byte for the point evaluation precompile.
	blobPrecompileReturnValue       = "000000000000000000000000000000000000000000000000000000000000100073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
)

var (
	errBlobVerifyInvalidInputLength = errors.New("invalid input length")
	errBlobVerifyMismatchedVersion  = errors.New("mismatched versioned hash")
	errBlobVerifyKZGProof           = errors.New("error verifying kzg proof")
)

func mockRun(input []byte) error {
	if len(input) != blobVerifyInputLength {
		return errBlobVerifyInvalidInputLength
	}
	// versioned hash: first 32 bytes
	var versionedHash common.Hash
	copy(versionedHash[:], input[:])

	var (
		point kzg4844.Point
		claim kzg4844.Claim
	)
	// Evaluation point: next 32 bytes
	copy(point[:], input[32:])
	// Expected output: next 32 bytes
	copy(claim[:], input[64:])

	// input kzg point: next 48 bytes
	var commitment kzg4844.Commitment
	copy(commitment[:], input[96:])
	if kZGToVersionedHash(commitment) != versionedHash {
		return errBlobVerifyMismatchedVersion
	}

	// Proof: next 48 bytes
	var proof kzg4844.Proof
	copy(proof[:], input[144:])

	if err := kzg4844.VerifyProof(commitment, point, claim, proof); err != nil {
		return fmt.Errorf("%w: %v", errBlobVerifyKZGProof, err)
	}

	return nil
}

func kZGToVersionedHash(kzg kzg4844.Commitment) common.Hash {
	h := sha256.Sum256(kzg[:])
	h[0] = blobCommitmentVersionKZG

	return h
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
