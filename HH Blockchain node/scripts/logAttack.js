import { network } from "hardhat";

const { ethers } = await network.create();

async function main() {
  const registryAddress = process.env.WARDEN_EVIDENCE_ADDRESS;

  if (!registryAddress) {
    throw new Error("Set WARDEN_EVIDENCE_ADDRESS first");
  }

  const evidence = await ethers.getContractAt("WardenEvidence", registryAddress);

  const evidenceHash =
    "0x96e0502eed7fad79c07f7620c13c026468418898f71af1b2fbd5c9c770a213ab";

  const tx = await evidence.logAttack(
    evidenceHash,
    "127.0.0.1",
    "MQTT",
    "PUBLISH",
    1000,
    true
  );

  const receipt = await tx.wait();
  console.log("Attack logged. tx:", receipt.hash);

  const count = await evidence.recordCount();
  console.log("Record count:", count.toString());

  const latest = await evidence.getLatestRecord();
  console.log("Latest record:", latest);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});