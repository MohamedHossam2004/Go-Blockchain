package main

import (
	"bytes"
	"encoding/gob"
	"time"
)

type Block struct {
    Timestamp     int64
    Transactions []*Transaction
    PrevBlockHash []byte
    Hash          []byte
    Nonce         int
}

func NewBlock(transactions []*Transaction, prevBlockHash []byte) *Block {
    block := &Block{time.Now().Unix(), transactions, prevBlockHash, []byte{}, 0}
    pow := NewProofOfWork(block)
    nonce, hash := pow.Run()

    block.Hash = hash[:]
    block.Nonce = nonce

    return block
}

func NewGenesisBlock(coinbase *Transaction) *Block {
    return NewBlock([]*Transaction{coinbase}, []byte{})
}

func (b *Block) HashTransactions() []byte {
    var transactions [][]byte

    for _, tx := range b.Transactions {
        transactions = append(transactions, tx.Serialize())
    }
    mTree := NewMerkleTree(transactions)

    return mTree.RootNode.Data
}

func (b *Block) Serialize() []byte {
	var result bytes.Buffer
	encoder := gob.NewEncoder(&result)

    _ = encoder.Encode(b)

	return result.Bytes()
}

func DeserializeBlock(d []byte) *Block{
	var block Block

	decoder := gob.NewDecoder(bytes.NewReader(d))
	_ = decoder.Decode(&block)

	return &block
}
