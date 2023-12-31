#!/bin/bash

# Use It When You Are Adding Two Package In Our Package That Imports Same Package, In Short It Can Help In Solving Diamond Package Problem
#     A
#   /   \
#  B     c
#   \   /
#     D
# 
# Note: D Is Your Package, If You Will Use Simple `go run .` Command You Will Failed To Run Program And Build Binary, 
# So To Resolve This Issue Use This Script 

go build --ldflags '-extldflags "-Wl,--allow-multiple-definition"' && ./tempop1011
