// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `npx hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
const hre = require("hardhat");
const fs = require("fs")
const path = require("path")

hre.web3.currentProvider.mySend = function(pl) {
    return new Promise((resolve, reject) => {
        this.send(pl, (err, r) => {
            if (err){
                reject(err)
            }else {
                resolve(r)
            }
        })
    })
}

async function main() {

    let bln = await hre.web3.eth.getBlockNumber()
    console.log('blk num', bln)
    let blk = await hre.web3.eth.getBlock(bln)
    console.log('blk', blk.hash)

    let {result: r} = await hre.web3.currentProvider.mySend({
        method:"eth_getBlockResultByHash",
        params: [blk.hash],
        jsonrpc: "2.0",
        id: new Date().getTime(),
    })

    let fd = fs.openSync(path.join(__dirname, '../', 'trace.json'), 'w')
    fs.writeFileSync(fd, JSON.stringify(r))
    fs.closeSync(fd)

/*    let execResult = r.executionResults[0]
    let digest = {
        gas: execResult.gas,
        failed: execResult.failed,
        storage: execResult.storage,
        codeHash: execResult.codeHash,
    }
    
    for (tr of digest.storage?.smtTrace || []) {
        //console.log(tr)
        console.log(JSON.stringify(tr))
    }
    for (log of execResult.structLogs) {
        if (log.op == "SSTORE"){
            console.log('stack', log.stack)
            console.log(JSON.stringify(log.extraData))
        }
    }
*/
}

  // We recommend this pattern to be able to use async/await everywhere
  // and properly handle errors.
  main()
    .then(() => {
        process.exit(0)
    })
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
  