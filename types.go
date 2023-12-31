package main

import (
	gethABI "github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/ethclient"
)

const (
	DeployTypeStr = "deploy"
	ReadTypeStr   = "read"
	CallTypeStr   = "call"
)

var RPCClients map[string]*ethclient.Client = map[string]*ethclient.Client{}
var WSSClients map[string]*ethclient.Client = map[string]*ethclient.Client{}
var ContractsMetaData map[string]*ContractMetaData = map[string]*ContractMetaData{}
var ContractsData map[string][]interface{} = map[string][]interface{}{}

type ContractMetaData struct {
	GethABI  *gethABI.ABI
	ByteCode []byte
}

type TransactionInstruction struct {
	Instructions []CallInstructions `yaml:"instructions"`
}

type Param struct {
	Data             interface{} `yaml:"data"`
	IsInstructionKey bool        `yaml:"isInstructionKey"`
}

type CallInstructions struct {
	Id              string             `yaml:"id"`
	Type            string             `yaml:"type"`
	Sequential      bool               `yaml:"sequential"`
	RpcURL          string             `yaml:"rpcURL"`
	WSSURL          string             `yaml:"wssURL"`
	SenderKey       string             `yaml:"senderKey"`
	ContractPath    string             `yaml:"contractPath"`
	ContractName    string             `yaml:"contractName"`
	ContractAddress string             `yaml:"contractAddress"`
	MethodName      string             `yaml:"methodName"`
	Params          []Param            `yaml:"params"`
	Value           int64              `yaml:"value"`
	GasLimit        uint64             `yaml:"gasLimit"`
	ChildCalls      []CallInstructions `yaml:"childCalls"`
}

type EncodeRequestBody struct {
	IsEncodeFunctionData bool        `json:"isEncodeFunctionData"`
	AbiPath              string      `json:"abiPath"`
	FunctionToCall       string      `json:"functionToCall"`
	Args                 interface{} `json:"args"`
}

type EncodeRequestResponse struct {
	Data  string `json:"data"`
	Error string `json:"error"`
}
