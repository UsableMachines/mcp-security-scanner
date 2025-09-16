#!/usr/bin/env node

/**
 * Simple test script to verify MCP Security Scanner basic functionality
 * This bypasses TypeScript compilation issues for quick testing
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('🔒 MCP Security Scanner Test');
console.log('============================\n');

// Test 1: Check if we can import the scanner
console.log('1. Testing TypeScript compilation...');
const tscResult = spawn('npx', ['tsc', '--noEmit'], { stdio: 'pipe' });

tscResult.stdout.on('data', (data) => {
  console.log(`   ${data}`);
});

tscResult.stderr.on('data', (data) => {
  console.log(`   Error: ${data}`);
});

tscResult.on('close', (code) => {
  if (code === 0) {
    console.log('   ✅ TypeScript compilation check passed\n');
    runBasicTests();
  } else {
    console.log('   ❌ TypeScript compilation has errors');
    console.log('   Suggestion: Fix TypeScript errors first, then test\n');
    runMinimalTests();
  }
});

function runBasicTests() {
  console.log('2. Testing configuration loading...');

  try {
    // Check if .env exists
    if (fs.existsSync('.env')) {
      const envContent = fs.readFileSync('.env', 'utf8');
      console.log('   ✅ .env file found');

      if (envContent.includes('KINDO_API_KEY')) {
        console.log('   ✅ KINDO_API_KEY configured');
      } else {
        console.log('   ⚠️  KINDO_API_KEY not found in .env - scanner will fail without it');
      }
    } else {
      console.log('   ⚠️  .env file not found - create one from .env.example');
    }

    console.log('');
  } catch (error) {
    console.log(`   ❌ Configuration test failed: ${error.message}\n`);
  }

  console.log('3. Testing package.json structure...');
  try {
    const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
    console.log(`   ✅ Project: ${packageJson.name} v${packageJson.version}`);
    console.log(`   ✅ Dependencies: ${Object.keys(packageJson.dependencies || {}).length} packages`);
    console.log('');
  } catch (error) {
    console.log(`   ❌ Package.json test failed: ${error.message}\n`);
  }
}

function runMinimalTests() {
  console.log('2. Running minimal functionality tests...\n');

  console.log('📁 Project Structure Check:');
  const criticalFiles = [
    'src/index.ts',
    'src/config/index.ts',
    'src/services/osv-service.ts',
    'src/analysis/dependency-analyzer.ts',
    'src/sandbox/sandbox-manager.ts',
    'src/analysis/ai-analyzer.ts'
  ];

  criticalFiles.forEach(file => {
    if (fs.existsSync(file)) {
      console.log(`   ✅ ${file}`);
    } else {
      console.log(`   ❌ ${file} - MISSING!`);
    }
  });

  console.log('\n📋 Available Commands:');
  const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  const scripts = packageJson.scripts || {};

  Object.keys(scripts).forEach(script => {
    console.log(`   yarn ${script.padEnd(12)} - ${scripts[script]}`);
  });

  console.log('\n🚀 Next Steps to Test:');
  console.log('   1. Fix TypeScript errors: yarn typecheck');
  console.log('   2. Set up .env with KINDO_API_KEY');
  console.log('   3. Try: yarn build');
  console.log('   4. Try: yarn dev');
}

// Test OSV API connectivity
console.log('4. Testing OSV.dev API connectivity...');
const https = require('https');

const testOSVAPI = () => {
  const postData = JSON.stringify({
    version: "1.0.0",
    package: {
      name: "lodash",
      ecosystem: "npm"
    }
  });

  const options = {
    hostname: 'api.osv.dev',
    port: 443,
    path: '/v1/query',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(postData)
    },
    timeout: 10000
  };

  const req = https.request(options, (res) => {
    if (res.statusCode === 200) {
      console.log('   ✅ OSV.dev API is accessible');
    } else {
      console.log(`   ⚠️  OSV.dev API returned status ${res.statusCode}`);
    }
    console.log('');
  });

  req.on('error', (error) => {
    console.log(`   ❌ OSV.dev API test failed: ${error.message}`);
    console.log('');
  });

  req.on('timeout', () => {
    console.log('   ⚠️  OSV.dev API request timed out');
    console.log('');
    req.destroy();
  });

  req.write(postData);
  req.end();
};

setTimeout(testOSVAPI, 1000);