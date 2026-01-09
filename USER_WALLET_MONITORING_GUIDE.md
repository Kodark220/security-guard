# User Wallet & dApp Contract Monitoring Guide

## Overview

The SecurityGuard contract now includes **proactive wallet monitoring** features that allow you to:
- ✅ Monitor contracts BEFORE you interact with them
- ✅ Get AI security analysis of specific transactions
- ✅ Track your interaction history with dApps
- ✅ Get warned about risky contracts
- ✅ Find safer alternatives to risky dApps

---

## 1. BEFORE YOU INTERACT: Pre-Interaction Analysis

### Step 1: Add a Contract to Your Watch List

When you discover a new dApp contract, add it immediately:

```javascript
// User action: "I found this new token contract, let me check it"
const result = await contract.add_contract_to_watch(
  "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  // USDC
  "USDC Token Contract"
);

// Returns:
{
  "success": true,
  "contract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
  "name": "USDC Token Contract",
  "risk_assessment": {
    "initial_risk": "low",
    "contract_type": "ERC20 Token",
    "risks_to_watch": ["large transfers", "approval scams"],
    "red_flags": [],
    "precautions": [
      "Verify contract address before approving",
      "Only approve minimum necessary amount",
      "Watch for unexpected transfer requests"
    ],
    "audit_needed": false
  },
  "monitoring_started": true,
  "alert_on": "high+ risk transactions"
}
```

---

## 2. ANALYZE BEFORE CLICKING CONFIRM

### Step 2: Pre-Interaction Security Check

**Before confirming ANY transaction**, get AI analysis:

```javascript
// User action: "I want to swap tokens on this DEX, is it safe?"

const analysis = await contract.analyze_contract_before_interaction(
  "0x1111111254fb6c44bac0bed2854e76f90643097d",  // 1Inch Router
  "swap",  // Function you want to call
  "tokenIn=0x..., tokenOut=0x..., amount=1000000",  // Params
  "0.5"  // ETH to send
);

// Returns:
{
  "status": "analyzed",
  "contract": "0x1111111254fb6c44bac0bed2854e76f90643097d",
  "function": "swap",
  "interaction_risk": "caution",  // ⚠️ Warning!
  "reason": "DEX aggregator with moderate risk - verify slippage settings",
  "precautions": [
    "Set max slippage to 0.5% or less",
    "Verify token addresses match what you expect",
    "Check 1inch fee is reasonable (usually 0%)",
    "Use small amount first to test"
  ],
  "should_proceed": true,  // OK to proceed but be careful
  "verify_before_confirming": [
    "token output amount is reasonable",
    "gas price is not unusually high",
    "contract address matches 1inch.io"
  ],
  "common_scams_to_watch": [
    "Fake token contract swaps",
    "Slippage set too high (losing funds)",
    "Contract address spoofing"
  ],
  "confidence_percent": 87,
  "action": "OK to proceed with caution"
}
```

### Step 3: Red Flags - DO NOT PROCEED

```javascript
// Example: Risky contract analysis

{
  "interaction_risk": "critical",  // 🚨 STOP!
  "reason": "Unknown contract attempting to transfer your tokens",
  "should_proceed": false,  // ❌ DO NOT PROCEED
  "action": "STOP - High Risk!",
  "common_scams_to_watch": [
    "Token stealing contract",
    "Infinite approval exploit",
    "Rug pull contract"
  ]
}
```

---

## 3. CHECK CONTRACT RISK PROFILE

### Get Full Risk Profile of Any Contract

```javascript
// User: "I want to review a contract's security before using it"

const profile = await contract.get_contract_risk_profile(
  "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984"  // UNI token
);

// Returns:
{
  "status": "monitored",
  "contract": "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984",
  "name": "Uniswap Token (UNI)",
  "risk_icon": "🟢",  // Safe!
  "initial_risk": "low",
  "contract_type": "ERC20 Governance Token",
  "risks_to_watch": [
    "Large holder dump risk",
    "Governance token manipulation"
  ],
  "red_flags": [],  // No red flags
  "precautions": [
    "Follow governance proposals",
    "Diversify holdings",
    "Watch whale movements"
  ],
  "audit_needed": false,  // Already audited
  "threats_detected": 0,  // No threats recorded
  "recommendation": "Safe to use"
}
```

---

## 4. TRACK YOUR INTERACTION HISTORY

### See All dApps You've Used

```javascript
// User: "Show me which dApps I've used and their security status"

const history = await contract.get_user_interaction_history(
  "0x742d35Cc6634C0532925a3b844Bc9e7595f97e5e"
);

// Returns:
{
  "user": "0x742d35Cc6634C0532925a3b844Bc9e7595f97e5e",
  "total_watched_contracts": 8,
  "watched_contracts": [
    {
      "contract": "0x1111111254fb6c44bac0bed2854e76f90643097d",
      "name": "1Inch Router",
      "risk": "medium",  // ⚠️ Medium risk
      "type": "DEX Aggregator",
      "interactions": 12
    },
    {
      "contract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
      "name": "USDC",
      "risk": "low",  // 🟢 Safe
      "type": "ERC20 Token",
      "interactions": 45
    },
    {
      "contract": "0xUnknownScam123",
      "name": "Suspicious Token",
      "risk": "critical",  // 🔴 CRITICAL - Stop using!
      "type": "Unknown",
      "interactions": 2
    }
  ],
  "total_interactions": 120,
  "recent_interactions": [
    {"contract": "0x1111...", "function": "swap", "timestamp": "2 hours ago"},
    {"contract": "0xA0b8...", "function": "transfer", "timestamp": "5 hours ago"}
  ],
  "high_risk_contracts": 2,  // ⚠️ Monitor these!
  "recommendation": "Monitor high-risk contracts closely"
}
```

---

## 5. MONITOR ALL YOUR dAPPS - DASHBOARD VIEW

### Security Team View

```javascript
// Security operator: "Give me overview of what users interact with"

const dappMonitoring = await contract.monitor_dapp_contracts();

// Returns:
{
  "status": "monitoring_active",
  "total_dapps_monitored": 23,
  "high_risk_dapps": 3,  // ⚠️ Need attention
  "safe_dapps": 15,       // 🟢 Safe
  "require_audit": 2,     // 🔍 Need security audit
  "dapp_list": [
    {
      "name": "Uniswap V3",
      "address": "0x...",
      "risk": "low",
      "type": "DEX",
      "red_flags": 0
    },
    {
      "name": "AAVE Lending",
      "address": "0x...",
      "risk": "low",
      "type": "Lending Protocol",
      "red_flags": 0
    },
    {
      "name": "Unknown Yield Farm",
      "address": "0x...",
      "risk": "critical",
      "type": "Yield Farming",
      "red_flags": 5
    }
  ],
  "alerts": 7,  // 7 pre-interaction warnings triggered
  "action_items": 5  // 5 contracts need review
}
```

---

## 6. FIND SAFER ALTERNATIVES

### Get Recommendations for Safer dApps

```javascript
// User: "Some of my dApps are risky. What are safer alternatives?"

const alternatives = await contract.get_safer_alternatives();

// Returns:
{
  "status": "recommendations_generated",
  "safer_alternatives": {
    "DEX": [
      {
        "recommended": "Uniswap V3",
        "why_safer": "Most audited, largest liquidity, transparent governance",
        "rating": "excellent"
      },
      {
        "recommended": "Curve Finance",
        "why_safer": "Specialized for stablecoins, low slippage, battle-tested",
        "rating": "excellent"
      }
    ],
    "Lending": [
      {
        "recommended": "AAVE",
        "why_safer": "Most established, fully audited, active governance",
        "rating": "excellent"
      },
      {
        "recommended": "Compound",
        "why_safer": "Pioneer in lending, conservative approach, audited",
        "rating": "good"
      }
    ]
  },
  "safety_tips": [
    "Always verify contract address on official website",
    "Start with small amounts when testing new dApps",
    "Use hardware wallet for large transactions",
    "Check contract audit reports before use",
    "Follow project governance and updates"
  ],
  "priority_switches": [
    "Move from unknown yield farm → AAVE (more secure)",
    "Use Uniswap instead of 1Inch for critical swaps"
  ],
  "message": "Review safer alternatives before interacting with high-risk contracts"
}
```

---

## WORKFLOW: USER SAFETY CHECKLIST

### Before Every Transaction:

```
1. NEW CONTRACT DISCOVERED
   ↓
   contract.add_contract_to_watch(address, name)
   
2. WANT TO INTERACT WITH IT
   ↓
   contract.analyze_contract_before_interaction(address, function, params, value)
   
3. CHECK ANALYSIS RESULT
   ├─ interaction_risk = "critical" → ❌ STOP
   ├─ interaction_risk = "dangerous" → ⚠️ Very risky, proceed with caution
   ├─ interaction_risk = "caution" → ⚠️ Medium risk, follow precautions
   └─ interaction_risk = "safe" → ✅ OK to proceed
   
4. VERIFY PRECAUTIONS
   ↓
   Read "verify_before_confirming" and "common_scams_to_watch"
   
5. CONFIRM TRANSACTION
   ↓
   Proceed with extra caution or use safer alternative
```

---

## EXAMPLE: Real World Scenario

### Scenario: New DeFi Protocol Offers Insane Yield

```javascript
// User discovers: Mega Yield Farm promising 500% APY

// Step 1: Check the contract
const riskProfile = await contract.get_contract_risk_profile(
  "0xMegaYieldFarm123"
);
// Returns: risk = "critical", audit_needed = true, red_flags = ["Rug pull risk"]

// Step 2: Analyze interaction before proceeding
const analysis = await contract.analyze_contract_before_interaction(
  "0xMegaYieldFarm123",
  "deposit",
  "amount=1000000",
  "0"
);
// Returns:
// - interaction_risk: "critical"
// - should_proceed: false
// - common_scams: ["Classic rug pull contract pattern"]
// - recommendation: "STOP - High Risk!"

// Step 3: Get safer alternatives
const alternatives = await contract.get_safer_alternatives();
// Shows: AAVE (audited, 8% APY), Curve (audited, 12% APY)

// Result: User skips risky farm, uses AAVE instead
// ✅ Protected from potential rug pull!
```

---

## Key Methods Summary

| Method | Use Case | Returns |
|--------|----------|---------|
| `add_contract_to_watch()` | Monitor new dApp | Risk profile + precautions |
| `analyze_contract_before_interaction()` | Pre-tx security check | Risk level + warnings + tips |
| `get_contract_risk_profile()` | Review contract | Complete risk assessment |
| `get_user_interaction_history()` | Audit your history | Contracts you use + risks |
| `monitor_dapp_contracts()` | Team overview | All monitored dApps + status |
| `get_safer_alternatives()` | Find safer options | Recommendations + reasons |

---

## Security Best Practices

1. **Always check BEFORE interacting** - Use analysis before confirming
2. **Start small** - Test with small amounts first
3. **Verify addresses** - Always verify contract address on official website
4. **Read precautions** - Follow the AI's specific security recommendations
5. **Use hardware wallet** - For large transactions or risky contracts
6. **Stop if critical** - If analysis says "critical" risk, DO NOT PROCEED
7. **Track history** - Monitor your interaction patterns
8. **Audit reports** - Check if contracts have been professionally audited

---

## What's Being Protected

- ✅ Token stealing contracts
- ✅ Rug pull protocols
- ✅ Infinite approval exploits
- ✅ Flash loan attacks
- ✅ Reentrancy vulnerabilities
- ✅ Slippage manipulation
- ✅ Contract impersonation
- ✅ Phishing contracts

---

## Next Steps

1. Connect your wallet
2. Open SecurityGuard dashboard
3. Add contracts you use to watch list
4. Before any transaction: click "Analyze This"
5. Review warnings and precautions
6. Follow recommendations
7. Check history regularly
8. Use safer alternatives when available

**Your wallet is now proactively protected! 🛡️**
