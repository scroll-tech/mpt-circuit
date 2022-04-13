// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `npx hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
const hre = require("hardhat");
const deploy = require("./deploy.json")

async function main() {

    const Token = await hre.ethers.getContractFactory("OpenZeppelinERC20TestToken");
    const addr = deploy.token
    if (!addr){
      throw 'no addr for token contract'
    }
    const token = Token.attach(addr)
    const targetAddr = hre.ethers.utils.getAddress( "0x8ba1f109551bd432803012645ac136ddd64dba72" )
    console.log('transfer before', await token.balanceOf(targetAddr))
    const tx = await token.transfer(targetAddr, 1000);
    await tx.wait()
    console.log('transfer after', await token.balanceOf(targetAddr))

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
  