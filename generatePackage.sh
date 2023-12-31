#!/bin/bash
solc --bin --abi contracts/temp.sol -o ./bin --overwrite

abigen --bin=./bin/Temp.bin --abi=./bin/Temp.abi --pkg=tempContract --out=./tempContract/tempContract.go