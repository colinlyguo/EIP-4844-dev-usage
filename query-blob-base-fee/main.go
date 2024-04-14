package main

import (
	"context"
	"math/big"
	"os"
	"time"

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

	log.Info("Starting to fetch block headers", "startBlock", latestSafeBlockNumber-numBlocksToFetch+1, "endBlock", latestSafeBlockNumber)

	startTime := time.Now()

	for i := latestSafeBlockNumber; i > latestSafeBlockNumber-numBlocksToFetch && i > 0; i-- {
		header, err := client.HeaderByNumber(context.Background(), big.NewInt(int64(i)))
		if err != nil {
			log.Warn("failed to get block header", "blockNumber", i, "err", err)
			continue
		}

		blobBaseFee := eip4844.CalcBlobFee(*header.ExcessBlobGas)
		totalBaseFee += header.BaseFee.Uint64()
		totalBlobBaseFee += blobBaseFee.Uint64()
		totalBlobNumber += (*header.BlobGasUsed) / 131072
		fetchedBlockCount++

		if fetchedBlockCount%10 == 0 {
			log.Info("Fetched block headers", "count", fetchedBlockCount)
		}
	}

	elapsedTime := time.Since(startTime)
	log.Info("Finished fetching block headers", "elapsedTime", elapsedTime)

	avgBaseFee := float64(totalBaseFee) / float64(fetchedBlockCount)
	avgBlobBaseFee := float64(totalBlobBaseFee) / float64(fetchedBlockCount)
	avgBlobNumber := float64(totalBlobNumber) / float64(fetchedBlockCount)

	log.Info("Network statistics",
		"numBlocks", fetchedBlockCount,
		"startBlock", latestSafeBlockNumber-numBlocksToFetch+1,
		"endBlock", latestSafeBlockNumber,
		"avgBaseFee", avgBaseFee,
		"avgBlobBaseFee", avgBlobBaseFee,
		"avgBlobNumber", avgBlobNumber,
		"estimated calldata cost / blob cost", 16*avgBaseFee/avgBlobBaseFee,
	)
}
