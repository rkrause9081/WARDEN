import { network } from "hardhat";

const { ethers } = await network.create();

async function main() {
  const [deployer] = await ethers.getSigners();

  console.log("Deploying with:", deployer.address);

  const Factory = await ethers.getContractFactory("WardenEvidenceFactory");
  const factory = await Factory.deploy();
  await factory.waitForDeployment();

  const factoryAddress = await factory.getAddress();
  console.log("WardenEvidenceFactory deployed to:", factoryAddress);

  const tx = await factory.createRegistry("WARDEN Local ICU Evidence Registry");
  const receipt = await tx.wait();

  const event = receipt.logs
    .map((log) => {
      try {
        return factory.interface.parseLog(log);
      } catch {
        return null;
      }
    })
    .find((parsed) => parsed && parsed.name === "RegistryCreated");

  const registryAddress = event.args.registry;
  console.log("WardenEvidence registry deployed to:", registryAddress);

  console.log("\nExport these before running Rust:");
  console.log("export WARDEN_FACTORY_ADDRESS=" + factoryAddress);
  console.log("export WARDEN_EVIDENCE_ADDRESS=" + registryAddress);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});