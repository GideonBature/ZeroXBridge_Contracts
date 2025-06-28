import { ethers } from "ethers";

async function signMessage() {
  // Create a random wallet for testing
  const wallet = ethers.Wallet.createRandom();
  console.log("Wallet address:", wallet.address);

  // Message to sign
  const commitmentHash =
    "1326957454500212857584915954277079662437048521450069746464967743209781177277";

  console.log("Commitment hash:", commitmentHash);

  // Sign the message
  const signature = await wallet.signMessage(commitmentHash);
  console.log("Signature:", signature);

  // Split the signature into r, s, v components
  const signatureBytes = ethers.getBytes(signature);
  const r = ethers.hexlify(signatureBytes.slice(0, 32));
  const s = ethers.hexlify(signatureBytes.slice(32, 64));
  const v = signatureBytes[64];

  console.log("r:", r);
  console.log("s:", s);
  console.log("v:", v);

  // Verify the signature
  const recoveredAddress = ethers.verifyMessage(commitmentHash, signature);
  console.log("Recovered signer address:", recoveredAddress);
  console.log("Signature verification:", recoveredAddress === wallet.address);
}

// Execute the function
signMessage().catch((error) => {
  console.error("Error:", error);
});
