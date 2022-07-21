// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `npx hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
const hre = require("hardhat");
const deploy = require("./deploy.json")
const utils = hre.ethers.utils

async function main() {

    const Vote = await hre.ethers.getContractFactory("VotesMock"); 
    const vote = Vote.attach(deploy.vote)
    console.log("total supply", await vote.getTotalSupply())

    const DAO = await hre.ethers.getContractFactory("GovernorMock");
    const addr = deploy.dao
    if (!addr){
      throw 'no addr for dao contract'
    }
    const dao = DAO.attach(addr)

    console.log("threshod", await dao.proposalThreshold())
    const value = new Date().getTime()

    let dummyAddr = hre.ethers.utils.getAddress( "0x0000000000000000000000000000000000000001" )
    const desc = "dao purpose test"
    let salt = utils.keccak256( utils.toUtf8Bytes(desc))
    let proposalId = await dao.hashProposal([dummyAddr], [value], ["0x00"], salt);

    const tx1 = await dao.propose([dummyAddr], [value], ["0x00"], desc)
    const tx2 = await dao.cancel([dummyAddr], [value], ["0x00"], salt)

    await Promise.all([tx1.wait(), tx2.wait()])
    console.log("get proposal state", await dao.state(proposalId)) //should be 2: canceled
    
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
  