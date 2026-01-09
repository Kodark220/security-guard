# Frontend Integration: User Wallet Monitor Dashboard

Example React component showing how to build a user-facing dashboard for wallet monitoring.

---

## 1. Contract Connection Setup

```javascript
// hookContractConnection.ts
import { ethers } from 'ethers';
import SecurityGuardABI from './SecurityGuardABI.json';

const CONTRACT_ADDRESS = "0x..."; // Your deployed contract address

export function useSecurityGuard() {
  const [contract, setContract] = useState(null);
  const [userAddress, setUserAddress] = useState(null);

  useEffect(() => {
    const initContract = async () => {
      const provider = new ethers.providers.Web3Provider(window.ethereum);
      const signer = provider.getSigner();
      const userAddr = await signer.getAddress();
      
      const securityGuard = new ethers.Contract(
        CONTRACT_ADDRESS,
        SecurityGuardABI,
        signer
      );
      
      setContract(securityGuard);
      setUserAddress(userAddr);
    };
    
    initContract();
  }, []);

  return { contract, userAddress };
}
```

---

## 2. Pre-Interaction Analysis Modal

```javascript
// PreInteractionAnalysis.tsx - Shows before user clicks "Confirm"
import React, { useState } from 'react';
import { useSecurityGuard } from './hookContractConnection';

export function PreInteractionModal({ 
  contractAddress, 
  functionName, 
  params, 
  valueEth,
  onCancel,
  onApprove 
}) {
  const { contract } = useSecurityGuard();
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const analyzeTransaction = async () => {
      try {
        const result = await contract.analyze_contract_before_interaction(
          contractAddress,
          functionName,
          JSON.stringify(params),
          valueEth
        );
        setAnalysis(result);
      } catch (error) {
        console.error('Analysis failed:', error);
      } finally {
        setLoading(false);
      }
    };

    analyzeTransaction();
  }, [contract, contractAddress, functionName, params, valueEth]);

  if (loading) return <div>🔍 Analyzing transaction security...</div>;

  const getRiskColor = (risk) => {
    if (risk === 'safe') return 'green';
    if (risk === 'caution') return 'yellow';
    if (risk === 'dangerous') return 'orange';
    if (risk === 'critical') return 'red';
    return 'gray';
  };

  const getRiskIcon = (risk) => {
    if (risk === 'safe') return '✅';
    if (risk === 'caution') return '⚠️';
    if (risk === 'dangerous') return '⚠️⚠️';
    if (risk === 'critical') return '🚨';
    return '❓';
  };

  return (
    <div className={`modal modal-${getRiskColor(analysis.interaction_risk)}`}>
      <h2>🔒 Security Check</h2>
      
      <div className="risk-badge">
        {getRiskIcon(analysis.interaction_risk)} 
        {analysis.interaction_risk.toUpperCase()}
      </div>

      <p className="reason">{analysis.reason}</p>

      <section className="precautions">
        <h3>⚠️ Precautions Before Confirming:</h3>
        <ul>
          {analysis.precautions.map((p, i) => (
            <li key={i}>✓ {p}</li>
          ))}
        </ul>
      </section>

      <section className="verify">
        <h3>🔍 Verify These:</h3>
        <ul>
          {analysis.verify_before_confirming.map((v, i) => (
            <li key={i}>□ {v}</li>
          ))}
        </ul>
      </section>

      {analysis.common_scams_to_watch?.length > 0 && (
        <section className="scams">
          <h3>🎣 Common Scams to Watch For:</h3>
          <ul>
            {analysis.common_scams_to_watch.map((s, i) => (
              <li key={i}>• {s}</li>
            ))}
          </ul>
        </section>
      )}

      <div className="actions">
        {!analysis.should_proceed ? (
          <>
            <button 
              onClick={onCancel} 
              className="btn btn-danger"
            >
              ❌ Cancel - Too Risky
            </button>
            <p className="warning">
              This transaction is flagged as high risk. We recommend NOT proceeding.
            </p>
          </>
        ) : (
          <>
            <button 
              onClick={onCancel} 
              className="btn btn-secondary"
            >
              Cancel
            </button>
            <button 
              onClick={onApprove} 
              className={`btn btn-${analysis.interaction_risk === 'safe' ? 'primary' : 'warning'}`}
            >
              ✅ Proceed With Caution
            </button>
          </>
        )}
      </div>

      <p className="confidence">
        Confidence: {analysis.confidence_percent}%
      </p>
    </div>
  );
}
```

---

## 3. Contract Watch List Dashboard

```javascript
// WatchListDashboard.tsx
import React, { useEffect, useState } from 'react';
import { useSecurityGuard } from './hookContractConnection';

export function WatchListDashboard() {
  const { contract, userAddress } = useSecurityGuard();
  const [watchList, setWatchList] = useState([]);
  const [newContractAddr, setNewContractAddr] = useState('');
  const [newContractName, setNewContractName] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!contract || !userAddress) return;
    loadWatchList();
  }, [contract, userAddress]);

  const loadWatchList = async () => {
    try {
      const history = await contract.get_user_interaction_history(userAddress);
      setWatchList(history.watched_contracts);
    } catch (error) {
      console.error('Failed to load watch list:', error);
    }
  };

  const addContractToWatch = async () => {
    if (!newContractAddr.trim() || !newContractName.trim()) {
      alert('Please fill in both fields');
      return;
    }

    setLoading(true);
    try {
      const result = await contract.add_contract_to_watch(
        newContractAddr,
        newContractName
      );
      
      if (result.success) {
        setNewContractAddr('');
        setNewContractName('');
        await loadWatchList();
      }
    } catch (error) {
      alert(`Error: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (risk) => {
    const colors = { low: '#10b981', medium: '#f59e0b', high: '#ef4444', critical: '#7f1d1d' };
    return colors[risk] || '#6b7280';
  };

  return (
    <div className="watch-list-container">
      <h1>👁️ My Watched Contracts</h1>

      <section className="add-contract">
        <h2>Add New Contract to Monitor</h2>
        <input
          type="text"
          placeholder="0x..."
          value={newContractAddr}
          onChange={(e) => setNewContractAddr(e.target.value)}
        />
        <input
          type="text"
          placeholder="Contract name"
          value={newContractName}
          onChange={(e) => setNewContractName(e.target.value)}
        />
        <button onClick={addContractToWatch} disabled={loading}>
          {loading ? '⏳ Adding...' : '➕ Add to Watch'}
        </button>
      </section>

      <section className="contracts-grid">
        <h2>Contracts You're Monitoring ({watchList.length})</h2>
        
        {watchList.length === 0 ? (
          <p>No contracts being monitored yet. Add one above!</p>
        ) : (
          <div className="grid">
            {watchList.map((contract) => (
              <div key={contract.contract} className="contract-card">
                <div className="header">
                  <h3>{contract.name}</h3>
                  <span 
                    className="risk-badge"
                    style={{ backgroundColor: getRiskColor(contract.risk) }}
                  >
                    {contract.risk.toUpperCase()}
                  </span>
                </div>
                
                <p className="address">{contract.contract.slice(0, 10)}...{contract.contract.slice(-8)}</p>
                <p className="type">{contract.type}</p>
                
                <div className="stats">
                  <div>📊 {contract.interactions} interactions</div>
                </div>

                <div className="actions">
                  <button className="btn-analyze">
                    🔍 Analyze Before Using
                  </button>
                  <button className="btn-profile">
                    📋 Full Profile
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
```

---

## 4. Interaction History & Recommendations

```javascript
// InteractionHistory.tsx
import React, { useEffect, useState } from 'react';
import { useSecurityGuard } from './hookContractConnection';

export function InteractionHistory() {
  const { contract, userAddress } = useSecurityGuard();
  const [history, setHistory] = useState(null);
  const [alternatives, setAlternatives] = useState(null);

  useEffect(() => {
    if (!contract || !userAddress) return;
    loadHistory();
    loadAlternatives();
  }, [contract, userAddress]);

  const loadHistory = async () => {
    try {
      const result = await contract.get_user_interaction_history(userAddress);
      setHistory(result);
    } catch (error) {
      console.error('Failed to load history:', error);
    }
  };

  const loadAlternatives = async () => {
    try {
      const result = await contract.get_safer_alternatives();
      setAlternatives(result);
    } catch (error) {
      console.error('Failed to load alternatives:', error);
    }
  };

  if (!history) return <div>⏳ Loading...</div>;

  return (
    <div className="history-container">
      <section className="overview">
        <h2>Your DApp Activity</h2>
        <div className="stats-grid">
          <div className="stat">
            <div className="number">{history.total_watched_contracts}</div>
            <div className="label">Contracts Monitored</div>
          </div>
          <div className="stat">
            <div className="number">{history.total_interactions}</div>
            <div className="label">Total Interactions</div>
          </div>
          <div className="stat warning">
            <div className="number">{history.high_risk_contracts}</div>
            <div className="label">⚠️ High Risk</div>
          </div>
        </div>
      </section>

      <section className="recommendations">
        <h2>🎯 Safer Alternatives</h2>
        {alternatives && Object.entries(alternatives.safer_alternatives).map(([useCase, alts]) => (
          <div key={useCase} className="use-case">
            <h3>{useCase.toUpperCase()}</h3>
            {alts.map((alt, i) => (
              <div key={i} className="alternative">
                <span className={`rating rating-${alt.rating}`}>
                  {alt.rating}
                </span>
                <div>
                  <strong>{alt.recommended}</strong>
                  <p>{alt.why_safer}</p>
                </div>
              </div>
            ))}
          </div>
        ))}
      </section>

      <section className="recent-activity">
        <h2>📝 Recent Activity</h2>
        {history.recent_interactions.map((interaction, i) => (
          <div key={i} className="activity-log">
            <span className="time">{interaction.timestamp}</span>
            <span className="function">{interaction.function}</span>
            <span className="contract">{interaction.contract.slice(0, 10)}...</span>
          </div>
        ))}
      </section>
    </div>
  );
}
```

---

## 5. Complete User Flow

```javascript
// App.tsx
import React, { useState } from 'react';
import { MetaMaskConnector } from '@web3-onboard/metamask';
import { useConnectWallet } from '@web3-onboard/react';

export function SecurityGuardApp() {
  const [{ wallet }, connect] = useConnectWallet();
  const [tab, setTab] = useState('dashboard');

  if (!wallet) {
    return (
      <div className="connect-wallet">
        <h1>🛡️ SecurityGuard - Wallet Protection</h1>
        <button onClick={() => connect()}>
          🔗 Connect Wallet
        </button>
      </div>
    );
  }

  return (
    <div className="app">
      <header>
        <h1>🛡️ SecurityGuard</h1>
        <p>Proactive DApp Security</p>
      </header>

      <nav>
        <button 
          className={tab === 'dashboard' ? 'active' : ''}
          onClick={() => setTab('dashboard')}
        >
          📊 Dashboard
        </button>
        <button 
          className={tab === 'watchlist' ? 'active' : ''}
          onClick={() => setTab('watchlist')}
        >
          👁️ Watch List
        </button>
        <button 
          className={tab === 'history' ? 'active' : ''}
          onClick={() => setTab('history')}
        >
          📈 History
        </button>
      </nav>

      <main>
        {tab === 'dashboard' && <SystemDashboard />}
        {tab === 'watchlist' && <WatchListDashboard />}
        {tab === 'history' && <InteractionHistory />}
      </main>
    </div>
  );
}
```

---

## 6. CSS Styling

```css
/* styles.css */

.modal {
  padding: 20px;
  border-radius: 8px;
  box-shadow: 0 4px 6px rgba(0,0,0,0.1);
}

.modal-safe { border-left: 4px solid #10b981; background: #ecfdf5; }
.modal-caution { border-left: 4px solid #f59e0b; background: #fffbeb; }
.modal-dangerous { border-left: 4px solid #ef4444; background: #fef2f2; }
.modal-critical { border-left: 4px solid #7f1d1d; background: #fee2e2; }

.risk-badge {
  display: inline-block;
  padding: 4px 12px;
  border-radius: 20px;
  font-weight: bold;
  font-size: 12px;
}

.contract-card {
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  padding: 16px;
  background: white;
}

.btn {
  padding: 10px 16px;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-weight: 600;
}

.btn-primary { background: #3b82f6; color: white; }
.btn-danger { background: #ef4444; color: white; }
.btn-secondary { background: #6b7280; color: white; }
.btn-warning { background: #f59e0b; color: black; }

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin: 16px 0;
}

.stat {
  padding: 16px;
  background: #f3f4f6;
  border-radius: 8px;
  text-align: center;
}

.stat .number {
  font-size: 32px;
  font-weight: bold;
  color: #3b82f6;
}

.stat.warning .number { color: #ef4444; }

.stat .label {
  margin-top: 8px;
  font-size: 14px;
  color: #6b7280;
}
```

---

## Integration Checklist

- [ ] Install ethers.js: `npm install ethers`
- [ ] Install web3-onboard: `npm install @web3-onboard/react @web3-onboard/metamask`
- [ ] Get contract ABI from deployment
- [ ] Set CONTRACT_ADDRESS constant
- [ ] Implement wallet connection
- [ ] Build modal component
- [ ] Build watch list dashboard
- [ ] Build history view
- [ ] Connect UI to contract methods
- [ ] Test with real contract
- [ ] Deploy frontend

---

## Key Integration Points

1. **Hook contract on wallet connect** - Get signer and create contract instance
2. **Show analysis modal BEFORE tx confirmation** - intercept MetaMask approval
3. **Update watch list on mount** - Load user's monitored contracts
4. **Track interactions** - Log when user interacts with watched contracts
5. **Display recommendations** - Show safer alternatives for risky dApps

This gives users **real-time, AI-powered protection** before they make expensive mistakes!
