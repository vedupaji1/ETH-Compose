package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"sync"

	gethABI "github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"gopkg.in/yaml.v3"
)

func informTransactionCompletion(rpcClient *ethclient.Client, wssURL string, txHash common.Hash) error {
	var wssClient *ethclient.Client
	if data, ok := RPCClients[wssURL]; ok {
		wssClient = data
	} else {
		client, err := ethclient.Dial(wssURL)
		if err != nil {
			return fmt.Errorf("failed to connect to wss ethclient: %v", err)
		}
		wssClient = client
		WSSClients[wssURL] = wssClient
	}
	blockResChan := make(chan *types.Header)
	subscribe, err := wssClient.SubscribeNewHead(context.Background(), blockResChan)
	if err != nil {
		return fmt.Errorf("failed to subscribe to wss ethclient: %v", err)
	}
	for {
		if _, isPending, _ := rpcClient.TransactionByHash(context.Background(), txHash); !isPending {
			return nil
		}
		select {
		case err := <-subscribe.Err():
			return fmt.Errorf("received error from subscription: %v", err)

		case data := <-blockResChan:
			blockData, err := rpcClient.BlockByNumber(context.Background(), data.Number)
			if err != nil {
				return fmt.Errorf("failed to get block data: %v", err)
			}
			for _, tx := range blockData.Transactions() {
				if tx.Hash() == txHash {
					return nil
				}
			}
		}
	}
}

func requestForEncodedData(isEncodeFunctionData bool, contractName string, functionToCall string, args interface{}) ([]byte, error) {
	hostURL := "http://localhost:8000/encodeData"
	requestBodyData := &EncodeRequestBody{
		IsEncodeFunctionData: isEncodeFunctionData,
		AbiPath:              "./bin/" + contractName + ".abi",
		FunctionToCall:       functionToCall,
		Args:                 args,
	}
	requestBodyPayload := new(bytes.Buffer)
	jsonEncoder := json.NewEncoder(requestBodyPayload)
	jsonEncoder.Encode(requestBodyData)
	request, err := http.NewRequest("POST", hostURL, bytes.NewBuffer(requestBodyPayload.Bytes()))
	if err != nil {
		return []byte{}, fmt.Errorf("failed to create request object: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to send request: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to read response body: %v", err)
	}
	responseData := &EncodeRequestResponse{}
	if err := json.Unmarshal(body, responseData); err != nil {
		return []byte{}, fmt.Errorf("failed to decode response body: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		return []byte{}, fmt.Errorf("received error from encoder server side: %v", string(body))
	}
	return hexutil.Decode(responseData.Data)
}

func getInstructionKeyData(mainInstructionKey string) (interface{}, error) {
	instructionKeys := strings.Split(mainInstructionKey, ".")
	var contractData []interface{}
	if data, ok := ContractsData[instructionKeys[0]]; ok {
		contractData = data
	} else {
		return nil, fmt.Errorf("failed to get instruction key data, invalid key is passed")
	}
	for i := 1; i < len(instructionKeys); i++ {
		dataIndex, err := strconv.Atoi(instructionKeys[i])
		if err != nil {
			return nil, fmt.Errorf("failed to convert string to int type: %v", err)
		}
		if data, ok := contractData[dataIndex].([]interface{}); ok {
			contractData = data
		} else {
			return contractData[dataIndex], nil
		}
	}
	return contractData, nil
}

func parseParams(params []Param) ([]interface{}, error) {
	res := []interface{}{}
	for _, data := range params {
		reflectValue := reflect.ValueOf(data)
		isInstructionKeyReflectValue := reflectValue.FieldByName("IsInstructionKey")
		paramValue := reflectValue.FieldByName("Data").Interface()
		if isInstructionKeyReflectValue.IsValid() {
			if isInstructionKeyReflectValue.Bool() {
				instructionKey, ok := reflectValue.FieldByName("Data").Interface().(string)
				if !ok {
					return nil, fmt.Errorf("instruction key data should be string")
				}
				instructionKeyData, err := getInstructionKeyData(instructionKey)
				if err != nil {
					return nil, err
				}
				paramValue = instructionKeyData
			}
		}
		res = append(res, paramValue)
	}
	return res, nil
}

func setupForTransaction(instructionData *CallInstructions) (*ethclient.Client, *ContractMetaData, *bind.TransactOpts, error) {
	var rpcClient *ethclient.Client
	if data, ok := RPCClients[instructionData.RpcURL]; ok {
		rpcClient = data
	} else {
		client, err := ethclient.Dial(instructionData.RpcURL)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to connect to rcp ethclient: %v", err)
		}
		rpcClient = client
		RPCClients[instructionData.RpcURL] = rpcClient
	}
	privateKey, err := crypto.HexToECDSA(instructionData.SenderKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create private key instance: %v", err)
	}
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, nil, fmt.Errorf("error casting public key to ECDSA")
	}
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := rpcClient.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get nonce: %v", err)
	}
	gasPrice, err := rpcClient.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get gasPrice: %v", err)
	}
	chainId, err := rpcClient.ChainID(context.Background())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get chain id: %v", err)
	}
	var contractMetaData *ContractMetaData
	if _, ok := ContractsMetaData[instructionData.ContractName]; !ok {
		if _, err := os.Stat(instructionData.ContractPath); err != nil {
			return nil, nil, nil, fmt.Errorf("invalid path of contract have been passed")
		}
		solcCompileCMD := exec.Command("solc", "--bin", "--abi", "--pretty-json", instructionData.ContractPath, "-o", "./bin", "--overwrite")
		_, err = solcCompileCMD.Output()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to generate abi and bytecode file: %v", err)
		}
		contractABI, err := os.ReadFile("./bin/" + instructionData.ContractName + ".abi")
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to read contract abi file: %v", err)
		}
		contractBin, err := os.ReadFile("./bin/" + instructionData.ContractName + ".bin")
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to read contract bytecode file: %v", err)
		}
		contractParsedABIForGethPKG, err := gethABI.JSON(strings.NewReader(string(contractABI)))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse contract abi for geth package: %v", err)
		}
		contractMetaData = &ContractMetaData{
			GethABI:  &contractParsedABIForGethPKG,
			ByteCode: common.FromHex("0x" + string(contractBin)),
		}
		ContractsMetaData[instructionData.ContractName] = contractMetaData
	} else {
		contractMetaData = ContractsMetaData[instructionData.ContractName]
	}
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainId)
	if err != nil {
		log.Panic("failed to generate tx auth: ", err)
	}
	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = big.NewInt(instructionData.Value)
	auth.GasPrice = gasPrice
	if int(instructionData.GasLimit) != 0 {
		auth.GasLimit = instructionData.GasLimit
	}
	return rpcClient, contractMetaData, auth, nil
}

func execute(wg *sync.WaitGroup, instructionData *CallInstructions) error {
	fmt.Printf("Executing Instruction, \nInstructionID: %v \nInstructionType: %v\n\n", instructionData.Id, instructionData.Type)
	if !instructionData.Sequential {
		defer wg.Done()
	}
	var contractAddress common.Address
	var tx *types.Transaction
	rpcClient, contractMetaData, auth, err := setupForTransaction(instructionData)
	if instructionData.Type == DeployTypeStr {
		if len(contractMetaData.GethABI.Constructor.Inputs) > 0 {
			parsedInputParams, err := parseParams(instructionData.Params)
			if err != nil {
				return fmt.Errorf("failed to parse input params: %v", err)
			}
			inputDataBytes, err := requestForEncodedData(false, instructionData.ContractName, "", parsedInputParams)
			if err != nil {
				return fmt.Errorf("failed to get encoded input data: %v", err)
			}
			inputData, err := contractMetaData.GethABI.Constructor.Inputs.UnpackValues(inputDataBytes)
			if err != nil {
				return fmt.Errorf("failed to unpack input data: %v", err)
			}
			contractAddress, tx, _, err = bind.DeployContract(auth, *contractMetaData.GethABI, contractMetaData.ByteCode, rpcClient, inputData...)
			if err != nil {
				return fmt.Errorf("failed to deploy contract: %v", err)
			}
		} else {
			contractAddress, tx, _, err = bind.DeployContract(auth, *contractMetaData.GethABI, contractMetaData.ByteCode, rpcClient)
			if err != nil {
				return fmt.Errorf("failed to deploy contract: %v", err)
			}
		}
		if err := informTransactionCompletion(rpcClient, instructionData.WSSURL, tx.Hash()); err != nil {
			fmt.Println("Something went wrong while listening for transaction completion: ", err)
		}
		ContractsData[instructionData.Id] = []interface{}{contractAddress}
		fmt.Printf("InstructionId: %v \nTxHash: %v \nContractDeployed: %v\n\n", instructionData.Id, tx.Hash(), contractAddress)
	} else if instructionData.Type == CallTypeStr {
		if common.IsHexAddress(instructionData.ContractAddress) {
			contractAddress = common.HexToAddress(instructionData.ContractAddress)
		} else {
			dataForInstruction, err := getInstructionKeyData(instructionData.ContractAddress)
			if err != nil {
				return fmt.Errorf("failed to get instruction data for contract: %v", err)
			}
			contractAddressParsed, ok := dataForInstruction.(common.Address)
			if !ok {
				return fmt.Errorf("failed to get contract address")
			}
			contractAddress = contractAddressParsed
		}
		contract := bind.NewBoundContract(contractAddress, *contractMetaData.GethABI, rpcClient, rpcClient, rpcClient)
		if len(contractMetaData.GethABI.Methods[instructionData.MethodName].Inputs) > 0 {
			parsedInputParams, err := parseParams(instructionData.Params)
			if err != nil {
				return fmt.Errorf("failed to parse input params: %v", err)
			}
			inputDataBytes, err := requestForEncodedData(true, instructionData.ContractName, instructionData.MethodName, parsedInputParams)
			if err != nil {
				return fmt.Errorf("failed to get encoded input data: %v", err)
			}
			inputData, err := contractMetaData.GethABI.Methods[instructionData.MethodName].Inputs.UnpackValues(inputDataBytes[4:])
			if err != nil {
				return fmt.Errorf("failed to unpack input data: %v", err)
			}
			tx, err = contract.Transact(auth, instructionData.MethodName, inputData...)
			if err != nil {
				return fmt.Errorf("failed to read contract method: %v", err)
			}
		} else {
			tx, err = contract.Transact(auth, instructionData.MethodName)
		}
		if err != nil {
			return fmt.Errorf("failed to call contract method: %v", err)
		}
		if err := informTransactionCompletion(rpcClient, instructionData.WSSURL, tx.Hash()); err != nil {
			fmt.Println("Something went wrong while listening for transaction completion: ", err)
		}
		fmt.Printf("InstructionId: %v \nTxHash: %v \nContractAddress: %v\n\n", instructionData.Id, tx.Hash(), contractAddress)
	} else if instructionData.Type == ReadTypeStr {
		if common.IsHexAddress(instructionData.ContractAddress) {
			contractAddress = common.HexToAddress(instructionData.ContractAddress)
		} else {
			dataForInstruction, err := getInstructionKeyData(instructionData.ContractAddress)
			if err != nil {
				return fmt.Errorf("failed to get instruction data for contract: %v", err)
			}
			contractAddressParsed, ok := dataForInstruction.(common.Address)
			if !ok {
				return fmt.Errorf("failed to get contract address")
			}
			contractAddress = contractAddressParsed
		}
		contract := bind.NewBoundContract(contractAddress, *contractMetaData.GethABI, rpcClient, rpcClient, rpcClient)
		res := []interface{}{}
		if len(contractMetaData.GethABI.Methods[instructionData.MethodName].Inputs) > 0 {
			parsedInputParams, err := parseParams(instructionData.Params)
			if err != nil {
				return fmt.Errorf("failed to parse input params: %v", err)
			}
			inputDataBytes, err := requestForEncodedData(true, instructionData.ContractName, instructionData.MethodName, parsedInputParams)
			if err != nil {
				return fmt.Errorf("failed to get encoded input data: %v", err)
			}
			inputData, err := contractMetaData.GethABI.Methods[instructionData.MethodName].Inputs.UnpackValues(inputDataBytes[4:])
			if err != nil {
				return fmt.Errorf("failed to unpack input data: %v", err)
			}
			if err := contract.Call(nil, &res, instructionData.MethodName, inputData...); err != nil {
				return fmt.Errorf("failed to read contract method: %v", err)
			}
		} else {
			if err := contract.Call(nil, &res, instructionData.MethodName); err != nil {
				return fmt.Errorf("failed to read contract method: %v", err)
			}
		}
		ContractsData[instructionData.Id] = res
		fmt.Printf("InstructionId: %v \nResData: %v \nContractAddress: %v\n\n", instructionData.Id, res, contractAddress)
	}
	executeInstructions(wg, false, instructionData.ChildCalls)
	return err
}

func executeInstructions(wg *sync.WaitGroup, isFirstFuncCall bool, configData []CallInstructions) {
	if isFirstFuncCall {
		defer wg.Done()
	}
	for i, instructionData := range configData {
		if instructionData.Sequential {
			if err := execute(wg, &configData[i]); err != nil {
				log.Fatal("sequential deploy instruction failed: ", err)
			}
		} else {
			wg.Add(1)
			go execute(wg, &configData[i])
		}
	}
}

func main() {
	cmdToCheckNodeJs := exec.Command("node", "-v")
	if _, err := cmdToCheckNodeJs.Output(); err != nil {
		log.Fatalf("nodejs not found, install nodejs: %v", err)
	}
	ctxForEncoderServer, stopEncoderServer := context.WithCancel(context.Background())
	defer stopEncoderServer()
	if err := exec.CommandContext(ctxForEncoderServer, "node", "./encoder/app.js").Start(); err != nil {
		log.Fatalf("failed to start encoder server: %v", err)
	}
	solcCheckCommand := exec.Command("solc", "--help")
	_, err := solcCheckCommand.Output()
	if err != nil {
		log.Fatal("solc compiler not found, make sure your system have solc compiler: ", err)
	}
	configFileDataInBytes, err := os.ReadFile("./config.yaml")
	if err != nil {
		log.Fatal("failed to read config file: ", err)
	}
	configFileData := &TransactionInstruction{}
	if err := yaml.Unmarshal(configFileDataInBytes, configFileData); err != nil {
		log.Fatal("failed to unmarshal config file data: ", err)
	}
	waitGroup := new(sync.WaitGroup)
	waitGroup.Add(1)
	go func(waitGroup *sync.WaitGroup) {
		wg := new(sync.WaitGroup)
		wg.Add(1)
		executeInstructions(wg, true, configFileData.Instructions)
		wg.Wait()
		fmt.Println("Execution Done")
		waitGroup.Done()

	}(waitGroup)
	waitGroup.Wait()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	<-sigChan
}
