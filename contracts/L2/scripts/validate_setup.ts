import { execSync } from "child_process";
import * as fs from "fs";
import * as dotenv from "dotenv";

// Load environment variables
dotenv.config();

interface ValidationResult {
    name: string;
    status: "✅" | "❌" | "⚠️";
    message: string;
}

async function validateSetup(): Promise<void> {
    console.log("🔍 Validating ZeroXBridge L2 Deployment Setup...\n");

    const results: ValidationResult[] = [];
    // Check environment variables
    const requiredEnvVars = ["STARKNET_PRIVATE_KEY", "STARKNET_ACCOUNT_ADDRESS"];
    const optionalEnvVars = ["STARKNET_RPC_URL", "OWNER_ADDRESS", "MIN_RATE", "MAX_RATE"];

    let allEnvPresent = true;
    let someEnvMissing = false;

    for (const envVar of requiredEnvVars) {
        if (process.env[envVar]) {
            results.push({
                name: `Environment Variable: ${envVar}`,
                status: "✅",
                message: "Set"
            });
        } else {
            results.push({
                name: `Environment Variable: ${envVar}`,
                status: "❌",
                message: "Required for deployment"
            });
            allEnvPresent = false;
        }
    }

    for (const envVar of optionalEnvVars) {
        if (process.env[envVar]) {
            results.push({
                name: `Environment Variable: ${envVar}`,
                status: "✅",
                message: "Set"
            });
        } else {
            results.push({
                name: `Environment Variable: ${envVar}`,
                status: "⚠️",
                message: "Optional - will prompt during deployment"
            });
            someEnvMissing = true;
        }
    }

    // Check if .env file exists
    if (fs.existsSync(".env")) {
        results.push({
            name: ".env file",
            status: "✅",
            message: "Found in project root"
        });
    } else {
        results.push({
            name: ".env file",
            status: "⚠️",
            message: "Not found - create one for easier deployment"
        });
    }

    // Check npm dependencies
    try {
        execSync("npm list --depth=0", { stdio: "pipe" });
        results.push({
            name: "NPM Dependencies",
            status: "✅",
            message: "All dependencies installed"
        });
    } catch {
        results.push({
            name: "NPM Dependencies",
            status: "❌",
            message: "Run 'npm install' to install dependencies"
        });
    }

    // Print results
    console.log("📋 Validation Results:");
    console.log("=====================\n");

    for (const result of results) {
        console.log(`${result.status} ${result.name}`);
        console.log(`   ${result.message}\n`);
    }

    // Summary
    const passCount = results.filter(r => r.status === "✅").length;
    const warnCount = results.filter(r => r.status === "⚠️").length;
    const failCount = results.filter(r => r.status === "❌").length;

    console.log("📊 Summary:");
    console.log("===========");
    console.log(`✅ Passed: ${passCount}`);
    console.log(`⚠️  Warnings: ${warnCount}`);
    console.log(`❌ Failed: ${failCount}\n`);

    if (failCount === 0) {
        console.log("🎉 Your environment is ready for deployment!");
        console.log("\nNext steps:");
        console.log("1. Set up your .env file with required credentials");
        console.log("2. Run 'npm run deploy:devnet' to test on local devnet");
        console.log("3. Run 'npm run deploy:testnet' for testnet deployment");
    } else {
        console.log("⚠️  Please fix the failed checks before deploying.");
        console.log("\nRecommended actions:");
        if (results.some(r => r.name.includes("snforge") && r.status === "❌")) {
            console.log("1. Install Starknet Foundry");
        }
        if (results.some(r => r.name.includes("Node.js") && r.status === "❌")) {
            console.log("2. Update Node.js to version 16 or higher");
        }
        if (results.some(r => r.name.includes("Dependencies") && r.status === "❌")) {
            console.log("3. Run 'npm install'");
        }
        if (!allEnvPresent) {
            console.log("4. Set up required environment variables");
        }
    }
}

// Run validation
validateSetup().catch(console.error); 