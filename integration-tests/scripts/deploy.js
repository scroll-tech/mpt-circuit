// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `npx hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
const hre = require("hardhat");
const fs = require("fs")
const path = require('path')

async function greeter() {
  // Hardhat always runs the compile task when running scripts with its command
  // line interface.
  //
  // If this script is run directly using `node` you may want to call compile
  // manually to make sure everything is compiled
  // await hre.run('compile');

  // We get the contract to deploy
  const Greeter = await hre.ethers.getContractFactory("Greeter");
  const greeter = await Greeter.deploy(0);

  await greeter.deployed();

  console.log("Greeter deployed to:", greeter.address);

  return ["greeter", greeter.address]
}

let greeterDep = greeter()

async function erc20() {

  const [owner] = await hre.ethers.getSigners();
  const ownerAddr = await owner.getAddress();

  // We get the contract to deploy
  const Token = await hre.ethers.getContractFactory("ERC20Template");
  const token = await Token.deploy(ownerAddr, ownerAddr, "USDT coin", "USDT", 18);

  await token.deployed();

  console.log("ERC20 token deployed to:", token.address);

  const tx = await token.mint(ownerAddr, BigInt("1000000000000000"))
  await tx.wait()
  console.log("mint done:", await token.balanceOf(ownerAddr));

  return ["token", token.address]
}

async function creater() {

  // We get the contract to deploy
  const Creater = await hre.ethers.getContractFactory("Creater");
  const creater = await Creater.deploy();

  await creater.deployed();

  console.log("Creater deployed to:", creater.address);

  return ["creater", creater.address]
}

async function caller() {

  let [_, greeterAddr] = await greeterDep

  // We get the contract to deploy
  const Caller = await hre.ethers.getContractFactory("Caller");
  const caller = await Caller.deploy(greeterAddr);

  await caller.deployed();

  console.log("Caller deployed to:", caller.address);

  return ["caller", caller.address]
}


async function sushi() {

  const Sushi = await hre.ethers.getContractFactory("SushiToken");
  const sushi = await Sushi.deploy();
  await sushi.deployed();

  console.log("sushi deployed to:", sushi.address);

  return ["sushi", sushi.address]
}

let sushiDep = sushi()

async function chef() {

  let [_, sushiAddr] = await sushiDep
  const [account] = await hre.ethers.getSigners();

  // We get the contract to deploy
  const Chef = await hre.ethers.getContractFactory("MasterChef");
  const chef = await Chef.deploy(sushiAddr, account.address,1,1,BigInt("9223372036854775807"));

  await chef.deployed();

  console.log("chef deployed to:", chef.address);

  const Sushi = await hre.ethers.getContractFactory("SushiToken");
  const sushi = Sushi.attach(sushiAddr)

  const tx1 = await sushi.mint(account.address, BigInt(1e22))
  const tx2 = await sushi.transferOwnership(chef.address)

  await Promise.all([tx1.wait(), tx2.wait()])
  console.log('sushi mint', await sushi.balanceOf(account.address))
	console.log("transfer token's ownership to chef")

  return ["sushiChef", chef.address]
}


async function nft() {

  const Nft = await hre.ethers.getContractFactory("ERC721Mock");
  const nft = await Nft.deploy("ERC721 coin", "ERC721");

  await nft.deployed();

  console.log("NFT deployed to:", nft.address);

  return ["nft", nft.address]
}

let voteDep = vote()

async function vote() {

  const Vote = await hre.ethers.getContractFactory("VotesMock");
  const vote = await Vote.deploy("vote v2");

  await vote.deployed();

  console.log("Vote deployed to:", vote.address);

  return ["vote", vote.address]
}

async function dao() {

  let [_, voteAddr] = await voteDep

  const Dao = await hre.ethers.getContractFactory("GovernorMock");
  const dao = await Dao.deploy("governor mock", voteAddr, 1, 1, 100);

  await dao.deployed();

  console.log("DAO deployed to:", dao.address);

  return ["dao", dao.address]
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
Promise.all([greeterDep, erc20(), creater(), caller(), nft(), sushiDep, chef(), voteDep, dao()])
  .then(res => {
    let fd = fs.openSync(path.join(__dirname, 'deploy.json'), 'w')
    fs.writeFileSync(fd, JSON.stringify(Object.fromEntries(res)))
    fs.closeSync(fd)
  }).catch((error) => {
    console.error(error);
    process.exit(1);
  });
