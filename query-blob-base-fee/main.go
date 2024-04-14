package main

import (
	"context"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/log"
	"github.com/joho/godotenv"
)

const numBlocksToFetch = 100

func main() {
	glogger := log.NewGlogHandler(log.NewTerminalHandler(os.Stderr, true))
	glogger.Verbosity(log.LevelInfo)
	log.SetDefault(log.NewLogger(glogger))

	err := godotenv.Load("../.env")
	if err != nil {
		log.Crit("failed to load .env file", "err", err)
	}

	client, err := ethclient.Dial(os.Getenv("RPC_PROVIDER_URL"))
	if err != nil {
		log.Crit("failed to connect to network", "err", err)
	}

	latestSafeBlock, err := client.HeaderByNumber(context.Background(), nil)
	if err != nil {
		log.Crit("failed to get latest safe block header", "err", err)
	}
	latestSafeBlockNumber := latestSafeBlock.Number.Uint64()

	var (
		totalBaseFee      uint64
		totalBlobBaseFee  uint64
		totalBlobNumber   uint64
		fetchedBlockCount uint64
	)

	for i := latestSafeBlockNumber; i > latestSafeBlockNumber-numBlocksToFetch && i > 0; i-- {
		header, err := client.HeaderByNumber(context.Background(), big.NewInt(int64(i)))
		if err != nil {
			log.Warn("failed to get block header", "blockNumber", i, "err", err)
			continue
		}

		blobBaseFee := eip4844.CalcBlobFee(*header.ExcessBlobGas)
		totalBaseFee = totalBaseFee + header.BaseFee.Uint64()
		totalBlobBaseFee = totalBlobBaseFee + blobBaseFee.Uint64()
		totalBlobNumber = totalBlobNumber + (*header.BlobGasUsed)/131072
		fetchedBlockCount++
	}

	avgBaseFee := 1.0 * totalBaseFee / fetchedBlockCount
	avgBlobBaseFee := 1.0 * totalBlobBaseFee / fetchedBlockCount
	avgBlobNumber := 1.0 * totalBlobNumber / fetchedBlockCount

	log.Info("Network statistics", "numBlocks", fetchedBlockCount, "startBlock", latestSafeBlockNumber-numBlocksToFetch+1, "endBlock", latestSafeBlockNumber, "avgBaseFee", avgBaseFee, "avgBlobBaseFee", avgBlobBaseFee, "avgBlobNumber", avgBlobNumber, "estimated calldata cost / blob cost", 16*avgBaseFee/avgBlobBaseFee)
}
