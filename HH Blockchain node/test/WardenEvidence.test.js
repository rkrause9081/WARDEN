import assert from "node:assert/strict";
import { network } from "hardhat";

let ethers;

before(async function () {
  ({ ethers } = await network.create());
});

describe("WardenEvidenceFactory", function () {
  it("deploys a registry", async function () {
    const Factory = await ethers.getContractFactory("WardenEvidenceFactory");
    const factory = await Factory.deploy();
    await factory.waitForDeployment();

    const tx = await factory.createRegistry("Test Registry");
    await tx.wait();

    assert.equal(await factory.registryCount(), 1n);

    const registryAddress = await factory.getRegistry(0);
    assert.ok(registryAddress.startsWith("0x"));
  });
});

describe("WardenEvidence", function () {
  it("logs an attack evidence record", async function () {
    const [owner] = await ethers.getSigners();

    const Evidence = await ethers.getContractFactory("WardenEvidence");
    const evidence = await Evidence.deploy("Test Registry", owner.address);
    await evidence.waitForDeployment();

    const hash =
      "0x96e0502eed7fad79c07f7620c13c026468418898f71af1b2fbd5c9c770a213ab";

    const tx = await evidence.logAttack(
      hash,
      "127.0.0.1",
      "MQTT",
      "PUBLISH",
      1000,
      true
    );
    await tx.wait();

    assert.equal(await evidence.recordCount(), 1n);

    const record = await evidence.getRecord(0);

    assert.equal(record.evidenceHash, hash);
    assert.equal(record.sourceIp, "127.0.0.1");
    assert.equal(record.protocol, "MQTT");
    assert.equal(record.messageType, "PUBLISH");
    assert.equal(record.ppsMilli, 1000n);
    assert.equal(record.mitigated, true);
  });

  it("rejects duplicate evidence hashes", async function () {
    const [owner] = await ethers.getSigners();

    const Evidence = await ethers.getContractFactory("WardenEvidence");
    const evidence = await Evidence.deploy("Test Registry", owner.address);
    await evidence.waitForDeployment();

    const hash =
      "0x96e0502eed7fad79c07f7620c13c026468418898f71af1b2fbd5c9c770a213ab";

    await evidence.logAttack(hash, "127.0.0.1", "MQTT", "PUBLISH", 1000, true);

    await assert.rejects(
      evidence.logAttack(hash, "127.0.0.1", "MQTT", "PUBLISH", 1000, true)
    );
  });
});