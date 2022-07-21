// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `npx hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
const hre = require("hardhat");
const deploy = require("./deploy.json")

async function main() {

    const Token = await hre.ethers.getContractFactory("ERC20");
    const addr = deploy.token
    if (!addr){
      throw 'no addr for token contract'
    }
    const token = Token.attach(addr)
    const [owner] = await hre.ethers.getSigners();
    console.log('my balance now', await token.balanceOf(owner.address))

    let pre_txs = [0,1,2,3,4].map(i => "0x000000000000000000000000000000000000000"+i)
      .map(hre.ethers.utils.getAddress)
      .map(addr => token.transfer(addr, 1000))
    
    let txs = await Promise.all(pre_txs)
    await Promise.all(txs.map(tx => tx.wait()))
    console.log('transfer after', await token.balanceOf(owner.address))

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
  