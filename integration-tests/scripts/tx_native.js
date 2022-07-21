// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `npx hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
const hre = require("hardhat");

async function main() {

    const [owner] = await hre.ethers.getSigners();
    console.log('my balance now', await owner.getBalance(), owner.address)

    let anotherAcc = new hre.ethers.Wallet("0x160276a92fce4c44039c24471f4c3ca7cacab358094ecd1b4863897eb2bcdba7", hre.ethers.provider)

    console.log('target balance before', await anotherAcc.getBalance())

    const tx = await owner.sendTransaction({
        to: anotherAcc.address,
        value: BigInt("10000000000000000"),
    })
    await tx.wait()

    console.log('target balance after', await anotherAcc.getBalance())
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
