// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `npx hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
const hre = require("hardhat");
const utils = hre.ethers.utils
//const fs = require("fs")
//const path = require("path")
const process = require("process")

// const {exec} = require("child_process")
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

    let addr = process.argv[2]
    if (!addr) {
        throw "must specify address"
    }
    addr = utils.getAddress(addr)

    let bln = "latest"
    let bln_arg = process.argv[3]
    if (bln_arg && !isNaN(parseInt(bln_arg))){
        bln = parseInt(bln_arg)
    }

    let keys = process.argv.slice(4)

    console.log('parameters: address, blk num, keys:', addr, bln, keys)

    let r = await hre.web3.eth.getProof(addr, keys, bln)

    console.log("------ output -------")
    console.log(JSON.stringify(r, null, '\t'))

/*    let fd = fs.openSync(path.join(__dirname, '../', 'proof.json'), 'w')
    fs.writeFileSync(fd, JSON.stringify(r))
    fs.closeSync(fd)*/
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
  