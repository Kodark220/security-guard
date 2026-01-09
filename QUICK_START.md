# SecurityGuard: Quick Start Guide

## 🎯 For Users: Protect Your Wallet

### In 3 Steps:

```
1. Found a new dApp?
   contract.add_contract_to_watch("0x...", "name")

2. About to interact?
   contract.analyze_contract_before_interaction("0x...", "function", params, value)

3. Risky contract?
   contract.get_safer_alternatives()
   → Get safer options recommended by AI
```

---

## 🛠️ For Developers: Integrate SecurityGuard

### Setup (5 minutes)

```javascript
// 1. Connect to your contract
const provider = new ethers.providers.Web3Provider(window.ethereum);
const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, signer);

// 2. Call a method
const analysis = await contract.analyze_contract_before_interaction(
  contractAddr,
  "swap",
  JSON.stringify({tokenIn: "0x...", amount: "1000000"}),
  "0.5"
);

// 3. Show user the result
if (analysis.should_proceed) {
  // Safe, show warning precautions
  console.log(analysis.precautions);
} else {
  // STOP! High risk
  console.log("🚨 STOP - Too risky!");
  console.log(analysis.common_scams_to_watch);
}
```

---

## 📊 All 7 New Methods

| Method | Purpose | Returns |
|--------|---------|---------|
| `add_contract_to_watch(addr, name)` | Start monitoring | Risk profile |
| `analyze_contract_before_interaction(addr, func, params, eth)` | Pre-tx check | Risk + warnings |
| `get_contract_risk_profile(addr)` | Full assessment | Complete profile |
| `get_user_interaction_history(user)` | Audit history | User's dApps |
| `monitor_dapp_contracts()` | Team dashboard | All monitored dApps |
| `get_safer_alternatives()` | Find better options | Recommendations |
| `system_health_check()` | System status | Health report |

---

## 🚀 Deploy

```bash
# 1. Deploy to GenLayer
genlayer deploy SecurityGuard.py --owner YOUR_ADDRESS

# 2. Get contract address
CONTRACT_ADDRESS="0x..."

# 3. Share with users
# Users can now monitor their wallets!
```

---

## ⚠️ Risk Levels

```
✅ SAFE       - Green light, go ahead
⚠️ CAUTION    - Yellow flag, follow precautions
⚠️ DANGEROUS  - Red flag, very risky
🚨 CRITICAL   - STOP! Do not proceed
```

---

## 🔐 Threats Detected

✅ Rug pulls
✅ Token stealing
✅ Approval exploits
✅ Phishing contracts
✅ Flash loan attacks
✅ Reentrancy bugs
✅ Slippage manipulation
✅ Contract spoofing

---

## 📱 Frontend Components Ready

See `FRONTEND_INTEGRATION_EXAMPLE.md` for:
- Pre-interaction modal
- Contract watch list
- Interaction history
- Safer alternatives view
- Complete React app

---

## 📚 Full Docs

- **USER_WALLET_MONITORING_GUIDE.md** - User guide
- **WALLET_MONITORING_SUMMARY.md** - Feature overview
- **FRONTEND_INTEGRATION_EXAMPLE.md** - React components
- **SecurityGuard.py** - Full contract code

---

## 🎓 Common Use Cases

### User: "Is this contract safe?"
```javascript
const profile = await contract.get_contract_risk_profile("0x...");
if (profile.initial_risk === "critical") {
  show_alternatives(); // Get safer options
}
```

### User: "What dApps have I used?"
```javascript
const history = await contract.get_user_interaction_history(userAddr);
console.log(history.watched_contracts); // All dApps with risk levels
```

### User: "Can I interact with this function?"
```javascript
const analysis = await contract.analyze_contract_before_interaction(
  "0x...",
  "swap",
  params,
  "0.5"
);
if (analysis.should_proceed === false) {
  alert("🚨 " + analysis.reason);
}
```

### Team: "Monitor all user activity"
```javascript
const dashboard = await contract.monitor_dapp_contracts();
console.log(`${dashboard.high_risk_dapps} risky dApps to review`);
```

---

## ✅ Deployment Checklist

- [ ] Deploy contract to GenLayer
- [ ] Get contract address
- [ ] Set CONTRACT_ADDRESS in frontend
- [ ] Build pre-interaction modal
- [ ] Build watch list dashboard
- [ ] Connect wallet with web3-onboard
- [ ] Test with real contract
- [ ] Deploy to mainnet
- [ ] Share with users
- [ ] Monitor activity

---

## 🆘 Troubleshooting

**Q: Analysis returns "unknown"?**
A: Contract not enough data yet, AI will improve with usage

**Q: Pre-interaction analysis is slow?**
A: LLM analysis takes 2-5 seconds, show loading spinner

**Q: Should_proceed is false, what now?**
A: Call get_safer_alternatives() and show user better options

**Q: How to display risk icons?**
A: Use: 🟢 safe, 🟡 caution, 🔴 dangerous, 🚨 critical

---

## 📞 Support

- GitHub: https://github.com/Kodark220/security-guard
- Issues: Open GitHub issue
- Docs: Check .md files in repo

---

## 🎉 You Now Have:

✅ AI-powered contract security
✅ Pre-interaction warnings
✅ User interaction tracking
✅ Safer alternative suggestions
✅ Team dashboard
✅ Complete React components
✅ Production-ready system

**Protect your users from bad dApps!** 🛡️
