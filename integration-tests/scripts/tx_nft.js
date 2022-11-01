// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `npx hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
const hre = require("hardhat");
const deploy = require("./deploy.json")

async function main() {

    const Nft = await hre.ethers.getContractFactory("ERC721Mock");
    const addr = deploy.nft
    if (!addr){
      throw 'no addr for nft contract'
    }
    const nft = Nft.attach(addr)
    const [owner] = await hre.ethers.getSigners();
    const tokenId = new Date().getTime()
    console.log('token existed', await nft.exists(tokenId), tokenId)

    // prepare for gas balance
    console.log('my balance now', await owner.getBalance())

    let anotherAcc = new hre.ethers.Wallet("0x160276a92fce4c44039c24471f4c3ca7cacab358094ecd1b4863897eb2bcdba7", hre.ethers.provider)
    const tx = await owner.sendTransaction({
        to: anotherAcc.address,
        value: BigInt("60000000000000000"), // ~ 10 times for burning
    })
    await tx.wait()
    console.log('target balance now', await anotherAcc.getBalance())

    const gPrice = await owner.getGasPrice()
    console.log('estimate gasprice', gPrice)
/*
    const tx0 = await nft.mint(owner.address, tokenId + 1)
    await tx0.wait()
    console.log('mine leading token', await nft.ownerOf(tokenId + 1))
    const tx01 = await nft.transferFrom(owner.address, anotherAcc.address, tokenId+1)
    await tx01.wait()
    console.log('nft owner after transfer is', await nft.ownerOf(tokenId+1))
*/
    // with 3 times of gasprice, we ensure the tx1/2 is executed before tx3
    const tx1 = await nft.mint(owner.address, tokenId, {gasPrice: gPrice * 3})
    const tx2 = await nft.transferFrom(owner.address, anotherAcc.address, tokenId, {gasPrice: gPrice * 2})
    const tx3 = await nft.connect(anotherAcc).burn(tokenId)

    await Promise.all([tx1.wait(), tx2.wait(), tx3.wait()])

    try {
      await nft.ownerOf(tokenId)
    } catch(e) {
      console.log("expect error")
    }
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
  