const { utils } = require("ethers");
const express = require("express");
const fs = require("fs");
const app = express();
const encoderServerPort = 8000;
app.use(express.json());
let contractInterfaces = {};

app.post("/encodeData", async (req, res) => {
  try {
    console.log(req.body);
    let contractInterface;
    if (contractInterfaces[req.body.abiPath] == undefined) {
      contractInterfaces[req.body.abiPath] = new utils.Interface(
        JSON.parse(fs.readFileSync(req.body.abiPath, { encoding: "utf8" }))
      );
    }
    contractInterface = contractInterfaces[req.body.abiPath];
    if (req.body.isEncodeFunctionData == true) {
      if (
        req.body.args != undefined &&
        req.body.args != null &&
        req.body.args.length > 0
      ) {
        res.status(200).json({
          data: contractInterface.encodeFunctionData(
            req.body.functionToCall,
            req.body.args
          ),
          error: "",
        });
        return;
      }
      res.status(200).json({
        data: contractInterface.encodeFunctionData(req.body.functionToCall),
        error: "",
      });
    } else {
      if (
        req.body.args != undefined &&
        req.body.args != null &&
        req.body.args.length > 0
      ) {
        res.status(200).json({
          data: contractInterface.encodeDeploy(req.body.args),
          error: "",
        });
        return
      }
      res.status(200).json({
        data: contractInterface.encodeDeploy(),
        error: "",
      });
    }
  } catch (error) {
    res.status(400).json({
      data: "",
      error: error.message,
    });
  }
});
app.listen(encoderServerPort, () => {
  console.log("Encoder Server Is Listening On Port: " + encoderServerPort);
});
