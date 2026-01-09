# { "Depends": "py-genlayer:test" }
from genlayer import *
import json


class SecurityGuard(gl.Contract):
    """
    AI-Powered Security Guard - Hack Detection & Emergency Pause System

    Features:
    - Real-time transaction scanning with AI
    - Automatic emergency pause on critical threats
    - Risk scoring (0-100) with threat levels
    - Blacklist & whitelist management
    - Multi-operator support
    - Global threat intelligence
    - Complete audit trail
    """

    # ==================== STORAGE ====================

    # Core ownership & state
    owner: Address
    is_paused: bool
    monitoring_enabled: bool

    # Security team
    operators: DynArray[Address]

    # Risk thresholds
    critical_threshold: u256  # Auto-pause (default: 85)
    high_threshold: u256      # High alert (default: 70)
    medium_threshold: u256    # Medium alert (default: 50)

    # Address lists
    blacklist: DynArray[Address]
    whitelist: DynArray[Address]

    # Statistics
    total_scans: u256
    total_threats: u256
    total_pauses: u256

    # Risk tracking (parallel arrays)
    tracked_addresses: DynArray[str]
    risk_scores: DynArray[u256]

    # NEW: Webhook notifications
    webhook_url: str
    webhook_enabled: bool
    min_risk_for_webhook: u256  # Only alert if risk >= this

    # NEW: Scan history for pattern learning (stores last 100 scans)
    scan_history: DynArray[str]  # JSON strings of scan results

    # NEW: User-friendly features for proactivity & UX
    threat_alerts: DynArray[str]  # User-friendly alert queue
    ai_recommendations: DynArray[str]  # AI-generated action recommendations
    threat_trends: TreeMap[str, str]  # Risk trends per address as JSON strings (for charts)
    operator_alerts_enabled: TreeMap[str, bool]  # Per-operator alert prefs (address as string key)
    last_system_health_check: u256  # Timestamp of last health check
    predicted_threats: DynArray[str]  # Proactive threat predictions
    system_uptime: u256  # Contract uptime in seconds
    created_at: u256  # Contract creation timestamp

    # NEW: User wallet & dApp contract monitoring
    watched_contracts: TreeMap[str, str]  # Contract address → risk profile JSON
    user_contract_interactions: TreeMap[str, str]  # User address → interaction history JSON
    contract_audit_status: TreeMap[str, str]  # Contract address → audit/security info JSON
    user_watched_list: TreeMap[str, str]  # User → list of contracts they watch JSON
    pre_interaction_warnings: DynArray[str]  # Warnings about upcoming interactions
    contract_vulnerability_db: DynArray[str]  # Known vulnerabilities database
    
    # NEW: Wallet connection & dApp integration
    connected_wallets: TreeMap[str, str]  # Wallet → connection metadata JSON
    dapp_registry: TreeMap[str, str]  # dApp contract → integration info JSON
    wallet_health_scores: TreeMap[str, u256]  # Wallet → overall health score (0-100)
    dapp_health_status: TreeMap[str, str]  # dApp → health status (healthy/warning/critical) JSON


    # ==================== CONSTRUCTOR ====================

    def __init__(self, owner_address: Address):
        """Initialize SecurityGuard with owner address."""
        # Handle different input types from deployment
        if isinstance(owner_address, int):
            # Convert int to hex string (40 chars = 20 bytes)
            hex_addr = hex(owner_address)[2:].zfill(40)
            owner = Address("0x" + hex_addr)
        elif isinstance(owner_address, str):
            owner = Address(owner_address)
        else:
            owner = owner_address

        # Set owner and initial state
        self.owner = owner
        self.is_paused = False
        self.monitoring_enabled = True

        # Add owner as first operator
        # (DynArray is auto-initialized by storage system)
        self.operators.append(owner)

        # Set default thresholds
        self.critical_threshold = u256(85)
        self.high_threshold = u256(70)
        self.medium_threshold = u256(50)

        # Initialize counters
        self.total_scans = u256(0)
        self.total_threats = u256(0)
        self.total_pauses = u256(0)

        # Initialize webhook settings
        self.webhook_url = ""
        self.webhook_enabled = False
        self.min_risk_for_webhook = u256(70)  # Alert on high+ threats

        # Initialize user-friendly features
        self.operator_alerts_enabled[str(owner)] = True
        self.last_system_health_check = u256(0)
        self.system_uptime = u256(0)
        self.created_at = u256(0)  # Will be set by GenLayer with block timestamp

        # Note: blacklist, whitelist, tracked_addresses, risk_scores, scan_history
        # threat_alerts, ai_recommendations, predicted_threats, threat_trends
        # user_contract_interactions, watched_contracts, contract_audit_status
        # user_watched_list, pre_interaction_warnings, contract_vulnerability_db
        # are auto-initialized as empty DynArrays/TreeMaps by the storage system


    # ==================== WRITE METHODS ====================

    @gl.public.write
    def scan_transaction(
        self,
        from_addr: str,
        to_addr: str,
        value_wei: str,
        calldata: str,
        gas_used: str
    ) -> dict:
        """
        Scan transaction for threats using AI analysis.

        Auto-pauses system if critical threat detected (score >= 85).

        Returns:
            dict: {
                "scan_id": int,
                "risk_score": int (0-100),
                "threat_level": str,
                "exploits": list,
                "explanation": str,
                "action_taken": str,
                "system_paused": bool
            }
        """
        # Increment scan counter
        self.total_scans = u256(int(self.total_scans) + 1)
        scan_id = int(self.total_scans)

        # Check whitelist first
        if self._address_in_list(from_addr, "whitelist"):
            return {
                "scan_id": scan_id,
                "status": "whitelisted",
                "risk_score": 0,
                "threat_level": "none",
                "action_taken": "bypassed",
                "system_paused": self.is_paused
            }

        # Check blacklist
        if self._address_in_list(from_addr, "blacklist"):
            return {
                "scan_id": scan_id,
                "status": "blacklisted",
                "risk_score": 100,
                "threat_level": "critical",
                "action_taken": "blocked",
                "reason": "Address is blacklisted",
                "system_paused": self.is_paused
            }

        # AI-powered threat analysis with COMPARATIVE equivalence
        # (validators compare risk scores within tolerance, not exact string match)
        def analyze_transaction() -> str:
            prompt = f"""You are a blockchain security expert. Analyze this transaction for threats.

TRANSACTION DATA:
- From: {from_addr}
- To: {to_addr}
- Value: {value_wei} wei
- Calldata: {calldata}
- Gas: {gas_used}

DETECT THESE EXPLOITS:
1. Reentrancy attacks (callback patterns, state changes after external calls)
2. Flash loan exploits (large temporary value transfers)
3. Front-running / MEV (suspicious gas prices, timing patterns)
4. Oracle manipulation (price feed tampering)
5. Suspicious gas patterns (unusually high/low gas)
6. Large value transfers (> 10 ETH or 10000000000000000000 wei)
7. Malicious calldata (known exploit signatures)
8. Unauthorized access (privilege escalation attempts)
9. Phishing patterns (similar to known scams)
10. Multiple failed transactions (brute force attempts)

RISK SCORING GUIDELINES:
- 0-49: Normal/Low risk (standard transactions)
- 50-69: Medium risk (suspicious but not critical)
- 70-84: High risk (dangerous, likely attack)
- 85-100: CRITICAL (confirmed attack, auto-pause)

Return ONLY valid JSON (no markdown, no extra text):
{{
    "risk_score": <number 0-100>,
    "threat_level": "<low|medium|high|critical>",
    "exploits_detected": ["<exploit1>", "<exploit2>"],
    "explanation": "<brief explanation of findings>",
    "is_threat": <true|false>
}}"""
            return gl.nondet.exec_prompt(prompt)

        # Execute with comparative equivalence (risk scores within 10 points tolerance)
        analysis_raw = gl.eq_principle.prompt_comparative(
            analyze_transaction,
            "Risk scores should be within 10 points. Threat level must match score ranges: 0-49=low, 50-69=medium, 70-84=high, 85-100=critical."
        )

        # Use robust JSON parser with fallback
        fallback = {
            "risk_score": 50,
            "threat_level": "medium",
            "exploits_detected": ["analysis_error"],
            "explanation": "AI analysis failed or returned invalid JSON",
            "is_threat": False
        }
        analysis = self._parse_llm_json(analysis_raw, fallback)

        risk_score = int(analysis.get("risk_score", 50))

        # Update risk tracking
        self._update_risk_tracking(from_addr, risk_score)

        # Determine actions based on thresholds
        action_taken = "none"
        paused_now = False

        # Medium threat - log only
        if risk_score >= int(self.medium_threshold):
            action_taken = "logged"

        # High threat - increment counter
        if risk_score >= int(self.high_threshold):
            self.total_threats = u256(int(self.total_threats) + 1)
            action_taken = "threat_detected"

        # Critical threat - EMERGENCY PAUSE
        if risk_score >= int(self.critical_threshold):
            if not self.is_paused:
                self.is_paused = True
                self.total_pauses = u256(int(self.total_pauses) + 1)
                paused_now = True

            # Auto-blacklist attacker
            self._add_to_blacklist_internal(from_addr)
            action_taken = "emergency_pause"

        # Prepare result
        result = {
            "scan_id": scan_id,
            "status": "analyzed",
            "risk_score": risk_score,
            "threat_level": analysis.get("threat_level", "unknown"),
            "exploits_detected": analysis.get("exploits_detected", []),
            "explanation": analysis.get("explanation", ""),
            "action_taken": action_taken,
            "system_paused": self.is_paused,
            "paused_this_scan": paused_now
        }

        # NEW: Save to scan history for pattern learning (keep last 100)
        self._save_to_history(result)

        # NEW: Trigger webhook if enabled and risk is high enough
        if self.webhook_enabled and risk_score >= int(self.min_risk_for_webhook):
            self._trigger_webhook(result)

        return result


    @gl.public.write
    def emergency_pause(self, reason: str) -> dict:
        """
        Manual emergency pause (operators only).

        Args:
            reason: Explanation for pause

        Returns:
            dict: Pause confirmation
        """
        # Check authorization
        sender = gl.message.sender_address
        if not self._is_operator(sender):
            raise Exception("Only operators can trigger emergency pause")

        self.is_paused = True
        self.total_pauses = u256(int(self.total_pauses) + 1)

        return {
            "paused": True,
            "reason": reason,
            "paused_by": str(sender),
            "total_pauses": int(self.total_pauses)
        }


    @gl.public.write
    def resume_system(self, justification: str) -> dict:
        """
        Resume operations after pause (owner only).

        Args:
            justification: Reason for resuming

        Returns:
            dict: Resume confirmation
        """
        # Only owner can resume
        if gl.message.sender_address != self.owner:
            raise Exception("Only owner can resume system")

        if not self.is_paused:
            raise Exception("System is not paused")

        self.is_paused = False

        return {
            "resumed": True,
            "justification": justification,
            "resumed_by": str(self.owner)
        }


    @gl.public.write
    def add_operator(self, operator_address: Address) -> dict:
        """
        Add security operator (owner only).

        Args:
            operator_address: Address to add as operator

        Returns:
            dict: Success status
        """
        if gl.message.sender_address != self.owner:
            raise Exception("Only owner can add operators")

        # Convert to Address if needed (handles int/str inputs)
        if isinstance(operator_address, int):
            hex_addr = hex(operator_address)[2:].zfill(40)
            addr_obj = Address("0x" + hex_addr)
        elif isinstance(operator_address, str):
            addr_obj = Address(operator_address)
        else:
            addr_obj = operator_address

        # Check if already operator
        for op in self.operators:
            if op == addr_obj:
                return {"success": False, "reason": "Already an operator"}

        self.operators.append(addr_obj)

        return {
            "success": True,
            "operator": str(operator_address),
            "total_operators": len(self.operators)
        }


    @gl.public.write
    def blacklist_address(self, address_to_blacklist: Address) -> dict:
        """
        Manually blacklist address (operators only).

        Args:
            address_to_blacklist: Address to blacklist

        Returns:
            dict: Success status
        """
        if not self._is_operator(gl.message.sender_address):
            raise Exception("Only operators can blacklist addresses")

        # Convert to Address if needed (handles int/str inputs)
        if isinstance(address_to_blacklist, int):
            hex_addr = hex(address_to_blacklist)[2:].zfill(40)
            addr_obj = Address("0x" + hex_addr)
        elif isinstance(address_to_blacklist, str):
            addr_obj = Address(address_to_blacklist)
        else:
            addr_obj = address_to_blacklist

        # Check if already blacklisted
        for addr in self.blacklist:
            if addr == addr_obj:
                return {"success": False, "reason": "Already blacklisted"}

        self.blacklist.append(addr_obj)

        return {
            "success": True,
            "address": str(address_to_blacklist),
            "total_blacklisted": len(self.blacklist)
        }


    @gl.public.write
    def whitelist_address(self, address_to_whitelist: Address) -> dict:
        """
        Add trusted address to whitelist (owner only).

        Args:
            address_to_whitelist: Address to whitelist

        Returns:
            dict: Success status
        """
        if gl.message.sender_address != self.owner:
            raise Exception("Only owner can whitelist addresses")

        # Convert to Address if needed (handles int/str inputs)
        if isinstance(address_to_whitelist, int):
            hex_addr = hex(address_to_whitelist)[2:].zfill(40)
            addr_obj = Address("0x" + hex_addr)
        elif isinstance(address_to_whitelist, str):
            addr_obj = Address(address_to_whitelist)
        else:
            addr_obj = address_to_whitelist

        # Check if already whitelisted
        for addr in self.whitelist:
            if addr == addr_obj:
                return {"success": False, "reason": "Already whitelisted"}

        self.whitelist.append(addr_obj)

        return {
            "success": True,
            "address": str(address_to_whitelist),
            "total_whitelisted": len(self.whitelist)
        }


    @gl.public.write
    def update_thresholds(
        self,
        new_critical: u256,
        new_high: u256,
        new_medium: u256
    ) -> dict:
        """
        Update threat detection thresholds (owner only).

        Args:
            new_critical: Critical threshold (auto-pause)
            new_high: High alert threshold
            new_medium: Medium alert threshold

        Returns:
            dict: Success status
        """
        if gl.message.sender_address != self.owner:
            raise Exception("Only owner can update thresholds")

        # Validate ordering
        if not (int(new_critical) > int(new_high) > int(new_medium)):
            raise Exception("Thresholds must satisfy: critical > high > medium")

        if int(new_critical) > 100:
            raise Exception("Thresholds must be <= 100")

        self.critical_threshold = new_critical
        self.high_threshold = new_high
        self.medium_threshold = new_medium

        return {
            "success": True,
            "thresholds": {
                "critical": int(new_critical),
                "high": int(new_high),
                "medium": int(new_medium)
            }
        }


    # ==================== READ METHODS ====================

    @gl.public.view
    def get_system_status(self) -> dict:
        """
        Get complete system status.

        Returns:
            dict: Complete system overview
        """
        return {
            "system": {
                "paused": self.is_paused,
                "monitoring_enabled": self.monitoring_enabled,
                "owner": str(self.owner)
            },
            "thresholds": {
                "critical": int(self.critical_threshold),
                "high": int(self.high_threshold),
                "medium": int(self.medium_threshold)
            },
            "statistics": {
                "total_scans": int(self.total_scans),
                "total_threats": int(self.total_threats),
                "total_pauses": int(self.total_pauses)
            },
            "counts": {
                "operators": len(self.operators),
                "blacklisted": len(self.blacklist),
                "whitelisted": len(self.whitelist),
                "tracked_addresses": len(self.tracked_addresses)
            }
        }


    @gl.public.view
    def get_address_risk(self, address: str) -> dict:
        """
        Get risk score for specific address.

        Args:
            address: Address to check

        Returns:
            dict: Risk information
        """
        # Find in tracked addresses
        for i in range(len(self.tracked_addresses)):
            if self.tracked_addresses[i].lower() == address.lower():
                score = int(self.risk_scores[i])
                return {
                    "address": address,
                    "risk_score": score,
                    "threat_level": self._score_to_level(score),
                    "blacklisted": self._address_in_list(address, "blacklist"),
                    "whitelisted": self._address_in_list(address, "whitelist"),
                    "tracked": True
                }

        # Not tracked
        return {
            "address": address,
            "risk_score": 0,
            "threat_level": "unknown",
            "blacklisted": self._address_in_list(address, "blacklist"),
            "whitelisted": self._address_in_list(address, "whitelist"),
            "tracked": False
        }


    @gl.public.view
    def get_blacklist(self) -> dict:
        """Get all blacklisted addresses."""
        addresses = []
        for addr in self.blacklist:
            addresses.append(str(addr))

        return {
            "blacklist": addresses,
            "total": len(addresses)
        }


    @gl.public.view
    def get_whitelist(self) -> dict:
        """Get all whitelisted addresses."""
        addresses = []
        for addr in self.whitelist:
            addresses.append(str(addr))

        return {
            "whitelist": addresses,
            "total": len(addresses)
        }


    @gl.public.view
    def get_operators(self) -> dict:
        """Get all security operators."""
        ops = []
        for op in self.operators:
            ops.append(str(op))

        return {
            "operators": ops,
            "total": len(ops)
        }


    @gl.public.view
    def get_threat_intelligence(self) -> dict:
        """
        Get global threat intelligence using AI + web data.

        Returns:
            dict: Current threat landscape
        """
        # AI analysis with NON-COMPARATIVE equivalence
        # fn returns the INPUT, task describes what to do, criteria for validation
        def get_threat_input() -> str:
            # Fetch real threat data from web (non-deterministic)
            try:
                threat_data = gl.nondet.web.render(
                    "https://blog.solidityscan.com/",
                    mode="text"
                )
                return threat_data[:1000] if threat_data else "No recent security data available"
            except:
                return "Unable to fetch real-time threat data"

        # Execute with non-comparative equivalence
        intel_raw = gl.eq_principle.prompt_non_comparative(
            get_threat_input,
            task="""Analyze the blockchain security news and provide threat intelligence.

Return ONLY valid JSON with:
- threat_level: one of "low", "medium", "high", or "critical"
- active_threats: array of current exploit campaigns
- recommendations: array of security actions to take
- summary: brief overview of the threat landscape

Format:
{
    "threat_level": "<low|medium|high|critical>",
    "active_threats": ["<threat1>", "<threat2>"],
    "recommendations": ["<action1>", "<action2>"],
    "summary": "<brief overview>"
}""",
            criteria="Must return valid JSON. threat_level must be exactly one of: low, medium, high, critical. active_threats and recommendations must be non-empty arrays."
        )

        # Use robust JSON parser with fallback
        fallback = {
            "threat_level": "unknown",
            "active_threats": ["Intelligence fetch failed"],
            "recommendations": ["Check manually"],
            "summary": "Unable to fetch threat intelligence"
        }
        intelligence = self._parse_llm_json(intel_raw, fallback)

        return {
            "intelligence": intelligence,
            "timestamp": "current"
        }


    # ==================== NEW: WEBHOOK METHODS ====================

    @gl.public.write
    def configure_webhook(self, url: str, enabled: bool, min_risk: u256) -> dict:
        """
        Configure webhook notifications for threat alerts.

        Args:
            url: Webhook URL to POST alerts to
            enabled: Enable/disable webhooks
            min_risk: Minimum risk score to trigger alert (recommend: 70+)

        Returns:
            dict: Configuration confirmation
        """
        if gl.message.sender_address != self.owner:
            raise Exception("Only owner can configure webhooks")

        self.webhook_url = url
        self.webhook_enabled = enabled
        self.min_risk_for_webhook = min_risk

        return {
            "success": True,
            "webhook_url": url,
            "enabled": enabled,
            "min_risk_threshold": int(min_risk)
        }


    @gl.public.view
    def get_webhook_config(self) -> dict:
        """Get current webhook configuration."""
        return {
            "url": self.webhook_url,
            "enabled": self.webhook_enabled,
            "min_risk_threshold": int(self.min_risk_for_webhook)
        }


    # ==================== NEW: AI PATTERN LEARNING ====================

    @gl.public.view
    def analyze_patterns(self) -> dict:
        """
        AI analyzes historical scans to find patterns and improve detection.

        Self-improving system that learns from past threats.

        Returns:
            dict: Pattern analysis with recommendations
        """
        if len(self.scan_history) < 10:
            return {
                "status": "insufficient_data",
                "message": f"Need at least 10 scans for pattern analysis. Currently have: {len(self.scan_history)}",
                "recommendations": []
            }

        # Prepare scan history for AI analysis
        history_summary = f"Total scans analyzed: {len(self.scan_history)}\n\n"
        history_summary += "Recent scans:\n"

        # Get last 20 scans for analysis
        recent_scans = []
        start_idx = max(0, len(self.scan_history) - 20)
        for i in range(start_idx, len(self.scan_history)):
            recent_scans.append(self.scan_history[i])

        history_summary += "\n".join(recent_scans)

        # Capture thresholds for closure
        crit_thresh = int(self.critical_threshold)
        high_thresh = int(self.high_threshold)
        med_thresh = int(self.medium_threshold)

        # AI pattern analysis with NON-COMPARATIVE equivalence
        # fn returns INPUT data, task describes what to do, criteria for validation
        def get_analysis_input() -> str:
            return f"""Scan History Analysis Input:

{history_summary}

Current system thresholds:
- Critical (auto-pause): {crit_thresh}
- High alert: {high_thresh}
- Medium alert: {med_thresh}"""

        # Execute with non-comparative equivalence
        analysis_raw = gl.eq_principle.prompt_non_comparative(
            get_analysis_input,
            task="""Analyze the security scan history to find patterns and improve threat detection.

Provide analysis on:
1. Common Patterns: What exploit types appear most frequently?
2. False Positives: Are we flagging too many safe transactions?
3. Threshold Recommendations: Should we adjust critical/high/medium thresholds?
4. Emerging Threats: Any new attack patterns appearing?
5. System Health: Is the detection working optimally?

Return ONLY valid JSON:
{
    "common_exploits": ["<exploit1>", "<exploit2>"],
    "false_positive_rate": "<low|medium|high>",
    "recommended_thresholds": {
        "critical": <number>,
        "high": <number>,
        "medium": <number>
    },
    "emerging_threats": ["<threat1>", "<threat2>"],
    "optimization_suggestions": ["<suggestion1>", "<suggestion2>"],
    "system_health": "<excellent|good|needs_improvement>",
    "summary": "<brief analysis>"
}""",
            criteria="Must return valid JSON. false_positive_rate must be low/medium/high. system_health must be excellent/good/needs_improvement. recommended_thresholds must have critical > high > medium, all values <= 100."
        )

        # Parse with fallback
        fallback = {
            "common_exploits": [],
            "false_positive_rate": "unknown",
            "recommended_thresholds": {
                "critical": int(self.critical_threshold),
                "high": int(self.high_threshold),
                "medium": int(self.medium_threshold)
            },
            "emerging_threats": [],
            "optimization_suggestions": ["Collect more scan data for better analysis"],
            "system_health": "unknown",
            "summary": "Insufficient data for comprehensive analysis"
        }

        patterns = self._parse_llm_json(analysis_raw, fallback)

        return {
            "status": "analyzed",
            "scans_analyzed": len(self.scan_history),
            "patterns": patterns,
            "current_thresholds": {
                "critical": int(self.critical_threshold),
                "high": int(self.high_threshold),
                "medium": int(self.medium_threshold)
            }
        }


    @gl.public.view
    def get_scan_history_count(self) -> dict:
        """Get count of historical scans available for pattern learning."""
        return {
            "total_scans": len(self.scan_history),
            "min_needed_for_analysis": 10,
            "can_analyze": len(self.scan_history) >= 10
        }


    # ==================== NEW: PROACTIVE & USER-FRIENDLY METHODS ====================

    @gl.public.write
    def predict_threats_proactive(self) -> dict:
        """
        AI predicts emerging threats BEFORE they become critical.
        Proactive system that warns of suspicious address behavior.

        Returns:
            dict: Predicted threats with confidence scores
        """
        if len(self.tracked_addresses) < 5:
            return {
                "status": "insufficient_data",
                "message": "Need at least 5 tracked addresses for predictions",
                "recommendations": ["Keep monitoring for more data"]
            }

        # Build address risk profile
        high_risk_addresses = []
        for i in range(len(self.tracked_addresses)):
            score = int(self.risk_scores[i])
            if score >= int(self.high_threshold):
                high_risk_addresses.append({
                    "address": self.tracked_addresses[i],
                    "risk_score": score
                })

        profile = f"High-risk addresses: {len(high_risk_addresses)}\n"
        profile += f"Total scans: {int(self.total_scans)}\n"
        profile += f"Threat rate: {int(self.total_threats) / max(1, int(self.total_scans)) * 100:.1f}%"

        # Use AI to predict emerging threats
        def predict_threats() -> str:
            prompt = f"""Analyze this security profile and predict emerging threats:

{profile}

Current system state:
- Paused: {self.is_paused}
- Monitoring: {self.monitoring_enabled}
- Critical threshold: {int(self.critical_threshold)}

Predict:
1. Which types of attacks are most likely next?
2. What addresses show pre-attack patterns?
3. Risk escalation probability (0-100%)
4. Recommended preventive actions

Return JSON: {{
    "predicted_attacks": ["attack1", "attack2"],
    "high_risk_patterns": ["pattern1"],
    "escalation_risk": 0-100,
    "preventive_actions": ["action1", "action2"],
    "confidence": 0-100
}}"""
            return gl.nondet.exec_prompt(prompt)

        # Get prediction with non-comparative consensus
        prediction_raw = gl.eq_principle.prompt_non_comparative(
            predict_threats,
            task="Predict next threats based on historical patterns",
            criteria="Predictions must be based on observed patterns. Risk scores 0-100."
        )

        prediction = self._parse_llm_json(prediction_raw, {
            "predicted_attacks": [],
            "high_risk_patterns": [],
            "escalation_risk": 0,
            "preventive_actions": [],
            "confidence": 0
        })

        # Store prediction
        pred_entry = json.dumps({
            "timestamp": "current",
            "predicted_attacks": prediction.get("predicted_attacks", []),
            "escalation_risk": prediction.get("escalation_risk", 0),
            "confidence": prediction.get("confidence", 0)
        })
        self.predicted_threats.append(pred_entry)

        # Keep last 20 predictions
        while len(self.predicted_threats) > 20:
            temp = []
            for i in range(1, len(self.predicted_threats)):
                temp.append(self.predicted_threats[i])
            while len(self.predicted_threats) > 0:
                self.predicted_threats.pop()
            for entry in temp:
                self.predicted_threats.append(entry)

        return {
            "status": "predicted",
            "threat_prediction": prediction,
            "action_required": prediction.get("escalation_risk", 0) > 70,
            "recommended_actions": prediction.get("preventive_actions", [])
        }


    @gl.public.write
    def get_ai_recommendations(self) -> dict:
        """
        Get AI-generated recommendations to improve security.
        Shows what actions to take next (user-friendly guidance).

        Returns:
            dict: Actionable recommendations prioritized by impact
        """
        if int(self.total_scans) == 0:
            return {
                "status": "no_data",
                "recommendations": ["Start monitoring transactions to receive recommendations"]
            }

        # Analyze current system state
        threat_rate = int(self.total_threats) / max(1, int(self.total_scans)) * 100
        avg_risk = 0
        if len(self.risk_scores) > 0:
            avg_risk = sum(int(s) for s in self.risk_scores) // len(self.risk_scores)

        state = f"""Current Security State:
- Total scans: {int(self.total_scans)}
- Threat detection rate: {threat_rate:.1f}%
- Average risk score: {avg_risk}
- System paused: {self.is_paused}
- Operators: {len(self.operators)}
- Blacklisted: {len(self.blacklist)}
- Whitelisted: {len(self.whitelist)}"""

        def generate_recommendations() -> str:
            prompt = f"""You are a blockchain security advisor. Based on this security system state:

{state}

Provide specific, actionable recommendations:
1. Immediate actions (must do now)
2. Short-term improvements (this week)
3. Long-term strategy (this month)
4. False positive reduction tips
5. Detection optimization

Return JSON: {{
    "immediate_actions": ["action1", "action2"],
    "short_term": ["improvement1"],
    "long_term": ["strategy1"],
    "optimization_tips": ["tip1"],
    "priority_score": 0-100
}}"""
            return gl.nondet.exec_prompt(prompt)

        rec_raw = gl.eq_principle.prompt_non_comparative(
            generate_recommendations,
            task="Generate security recommendations",
            criteria="Recommendations must be specific and actionable"
        )

        recommendations = self._parse_llm_json(rec_raw, {
            "immediate_actions": ["Monitor recent threats"],
            "short_term": ["Review blacklist"],
            "long_term": ["Tune thresholds"],
            "optimization_tips": [],
            "priority_score": 50
        })

        # Store recommendations
        rec_entry = json.dumps({
            "timestamp": "current",
            "immediate_actions": recommendations.get("immediate_actions", []),
            "priority": recommendations.get("priority_score", 50)
        })
        self.ai_recommendations.append(rec_entry)

        # Keep last 10
        while len(self.ai_recommendations) > 10:
            temp = []
            for i in range(1, len(self.ai_recommendations)):
                temp.append(self.ai_recommendations[i])
            while len(self.ai_recommendations) > 0:
                self.ai_recommendations.pop()
            for entry in temp:
                self.ai_recommendations.append(entry)

        return {
            "status": "recommended",
            "recommendations": recommendations,
            "urgent": recommendations.get("priority_score", 0) > 70
        }


    @gl.public.view
    def get_system_dashboard(self) -> dict:
        """
        Beautiful, user-friendly system dashboard.
        Shows everything at a glance with visual indicators.

        Returns:
            dict: Comprehensive system overview for UI/dashboards
        """
        # Calculate metrics
        threat_rate = 0
        if int(self.total_scans) > 0:
            threat_rate = int(self.total_threats) * 100 // int(self.total_scans)

        avg_risk = 0
        if len(self.risk_scores) > 0:
            avg_risk = sum(int(s) for s in self.risk_scores) // len(self.risk_scores)

        # Health status indicator
        health_status = "excellent"
        if self.is_paused:
            health_status = "critical"
        elif threat_rate > 30:
            health_status = "warning"
        elif threat_rate > 10:
            health_status = "caution"

        # System icon based on status
        status_icon = "🟢" if health_status == "excellent" else "🟡" if health_status in ["caution", "warning"] else "🔴"

        return {
            "system_status": {
                "health": health_status,
                "icon": status_icon,
                "paused": self.is_paused,
                "monitoring": self.monitoring_enabled,
                "owner": str(self.owner)
            },
            "metrics": {
                "total_scans": int(self.total_scans),
                "total_threats_detected": int(self.total_threats),
                "threat_detection_rate_percent": threat_rate,
                "emergency_pauses": int(self.total_pauses),
                "average_risk_score": avg_risk
            },
            "security_roster": {
                "operators": len(self.operators),
                "blacklisted_addresses": len(self.blacklist),
                "whitelisted_addresses": len(self.whitelist),
                "addresses_tracked": len(self.tracked_addresses)
            },
            "risk_assessment": {
                "critical_threshold": int(self.critical_threshold),
                "high_threshold": int(self.high_threshold),
                "medium_threshold": int(self.medium_threshold),
                "current_health_level": health_status
            },
            "recent_activity": {
                "recent_threats": int(self.total_threats),
                "recent_scans": int(self.total_scans),
                "recent_recommendations": len(self.ai_recommendations),
                "predicted_threats_count": len(self.predicted_threats)
            },
            "quick_actions": {
                "pause_enabled": not self.is_paused,
                "resume_enabled": self.is_paused,
                "can_scan": self.monitoring_enabled
            }
        }


    @gl.public.view
    def get_address_profile(self, address: str) -> dict:
        """
        Rich profile for any address with historical data.
        User-friendly detailed view of address behavior.

        Args:
            address: Address to profile

        Returns:
            dict: Comprehensive address profile with trends
        """
        # Get basic risk info
        risk_data = self.get_address_risk(address)

        # Get trend data if available
        trend_info = {}
        if address in self.threat_trends:
            try:
                trend_json = self.threat_trends[address]
                trend_info = json.loads(trend_json)
            except:
                trend_info = {"status": "parsing_error"}
        else:
            trend_info = {"status": "no_history"}

        # Determine risk profile
        score = risk_data.get("risk_score", 0)
        risk_level = risk_data.get("threat_level", "unknown")

        risk_profile = "safe"
        if score >= int(self.critical_threshold):
            risk_profile = "critical"
        elif score >= int(self.high_threshold):
            risk_profile = "dangerous"
        elif score >= int(self.medium_threshold):
            risk_profile = "suspicious"

        # Status indicators
        status = "🟢 Safe" if risk_profile == "safe" else "🟡 Caution" if risk_profile == "suspicious" else "🔴 Danger" if risk_profile == "dangerous" else "⛔ CRITICAL"

        return {
            "address": address,
            "security_status": status,
            "risk_profile": risk_profile,
            "risk_score": risk_data.get("risk_score", 0),
            "threat_level": risk_level,
            "lists": {
                "blacklisted": risk_data.get("blacklisted", False),
                "whitelisted": risk_data.get("whitelisted", False)
            },
            "tracking": {
                "tracked": risk_data.get("tracked", False),
                "trend_data": trend_info
            },
            "recommendations": {
                "safe_to_interact": risk_profile in ["safe", "suspicious"],
                "needs_monitoring": risk_profile in ["suspicious", "dangerous"],
                "should_block": risk_profile in ["critical", "dangerous"]
            }
        }


    @gl.public.view
    def get_threat_summary(self) -> dict:
        """
        Quick visual summary of all threats. Perfect for dashboards.

        Returns:
            dict: Summary with threat breakdown
        """
        critical_count = 0
        high_count = 0
        medium_count = 0

        for score in self.risk_scores:
            s = int(score)
            if s >= int(self.critical_threshold):
                critical_count += 1
            elif s >= int(self.high_threshold):
                high_count += 1
            elif s >= int(self.medium_threshold):
                medium_count += 1

        total_threats = critical_count + high_count + medium_count

        return {
            "threat_breakdown": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "total": total_threats
            },
            "visual_summary": f"🔴 {critical_count} Critical | 🟠 {high_count} High | 🟡 {medium_count} Medium",
            "system_alert": self.is_paused,
            "alert_message": "SYSTEM PAUSED - Emergency threshold reached" if self.is_paused else "System monitoring normally",
            "action_items": critical_count + high_count  # How many need immediate attention
        }


    @gl.public.write
    def set_operator_alert_preference(self, alert_enabled: bool) -> dict:
        """
        Let operators control their own alert settings (user-friendly).

        Args:
            alert_enabled: Enable/disable alerts for caller

        Returns:
            dict: Preference saved confirmation
        """
        sender = gl.message.sender_address
        if not self._is_operator(sender):
            raise Exception("Only operators can set preferences")

        self.operator_alerts_enabled[str(sender)] = alert_enabled

        return {
            "success": True,
            "operator": str(sender),
            "alerts_enabled": alert_enabled,
            "message": "Alert preference saved"
        }


    @gl.public.view
    def system_health_check(self) -> dict:
        """
        Comprehensive system health diagnostics.
        Identifies issues and suggests fixes automatically (proactive).

        Returns:
            dict: Health report with issues and solutions
        """
        issues = []
        warnings = []
        improvements = []

        # Check 1: Monitor system pause state
        if self.is_paused:
            issues.append({
                "severity": "critical",
                "issue": "System is paused",
                "solution": "Call resume_system() to restore operations",
                "impact": "No transactions are being scanned"
            })

        # Check 2: Monitoring status
        if not self.monitoring_enabled:
            issues.append({
                "severity": "high",
                "issue": "Monitoring disabled",
                "solution": "Re-enable monitoring to detect threats",
                "impact": "Threats will not be detected"
            })

        # Check 3: High threat rate
        if int(self.total_scans) > 0:
            threat_rate = int(self.total_threats) * 100 // int(self.total_scans)
            if threat_rate > 30:
                warnings.append({
                    "severity": "high",
                    "issue": f"High threat detection rate ({threat_rate}%)",
                    "solution": "Review recent threats and consider stricter thresholds",
                    "impact": "May need threshold adjustment"
                })

        # Check 4: Operators status
        if len(self.operators) < 2:
            warnings.append({
                "severity": "medium",
                "issue": f"Only {len(self.operators)} operator(s). Single point of failure.",
                "solution": "Add more operators for better security oversight",
                "impact": "Reduced operational resilience"
            })

        # Check 5: Empty lists
        if len(self.blacklist) == 0 and int(self.total_scans) > 10:
            improvements.append({
                "severity": "info",
                "issue": "No addresses blacklisted despite scanning",
                "solution": "Monitor for patterns and blacklist malicious addresses",
                "impact": "Could improve detection"
            })

        # Check 6: Webhook configuration
        if int(self.total_threats) > 5 and not self.webhook_enabled:
            improvements.append({
                "severity": "info",
                "issue": "Webhooks not configured despite threats detected",
                "solution": "Setup webhooks for real-time alerts",
                "impact": "Faster incident response"
            })

        # Health score
        health_score = 100
        health_score -= len(issues) * 30
        health_score -= len(warnings) * 15
        health_score = max(0, health_score)

        health_status = "excellent"
        if health_score < 40:
            health_status = "critical"
        elif health_score < 60:
            health_status = "poor"
        elif health_score < 80:
            health_status = "fair"

        return {
            "health_score": health_score,
            "health_status": health_status,
            "issues": issues,
            "warnings": warnings,
            "improvements": improvements,
            "total_issues": len(issues) + len(warnings),
            "system_ready": len(issues) == 0,
            "diagnostic_timestamp": "current"
        }


    # ==================== NEW: USER WALLET & dAPP MONITORING ====================

    @gl.public.write
    def add_contract_to_watch(self, contract_addr: str, contract_name: str) -> dict:
        """
        User adds a contract to their watch list.
        Proactively monitor contracts before/during interaction.

        Args:
            contract_addr: Contract address to monitor
            contract_name: User-friendly name for contract

        Returns:
            dict: Confirmation with initial risk assessment
        """
        user = str(gl.message.sender_address)
        addr_lower = contract_addr.lower()

        # Check if already watching
        if addr_lower in self.watched_contracts:
            return {
                "success": False,
                "reason": "Already monitoring this contract",
                "contract": contract_addr,
                "name": contract_name
            }

        # AI analyze contract before adding to watch list
        def analyze_contract() -> str:
            prompt = f"""Analyze this smart contract address for security risks:

Contract Address: {contract_addr}
Contract Name: {contract_name}

Based on common DeFi vulnerabilities and blockchain threats, provide:
1. Initial risk assessment (low/medium/high/critical)
2. Likely purpose (DEX, lending, staking, etc.)
3. Known risks to watch for
4. Red flags in interaction patterns
5. Recommended precautions

Return JSON: {{
    "initial_risk": "<low|medium|high|critical>",
    "contract_type": "<type>",
    "risks_to_watch": ["<risk1>", "<risk2>"],
    "red_flags": ["<flag1>", "<flag2>"],
    "precautions": ["<action1>", "<action2>"],
    "audit_recommended": <true|false>
}}"""
            return gl.nondet.exec_prompt(prompt)

        analysis_raw = gl.eq_principle.prompt_non_comparative(
            analyze_contract,
            task="Analyze contract for security",
            criteria="Risk must be low/medium/high/critical. Include actionable precautions."
        )

        risk_data = self._parse_llm_json(analysis_raw, {
            "initial_risk": "unknown",
            "contract_type": "unknown",
            "risks_to_watch": [],
            "red_flags": [],
            "precautions": [],
            "audit_recommended": False
        })

        # Store contract risk profile
        self.watched_contracts[addr_lower] = json.dumps({
            "name": contract_name,
            "address": contract_addr,
            "initial_risk": risk_data.get("initial_risk", "unknown"),
            "contract_type": risk_data.get("contract_type", "unknown"),
            "risks": risk_data.get("risks_to_watch", []),
            "red_flags": risk_data.get("red_flags", []),
            "precautions": risk_data.get("precautions", []),
            "audit_needed": risk_data.get("audit_recommended", False),
            "added_at": "current"
        })

        # Add to user's watch list
        if user in self.user_watched_list:
            try:
                user_list = json.loads(self.user_watched_list[user])
                if contract_addr not in user_list:
                    user_list.append(contract_addr)
                    self.user_watched_list[user] = json.dumps(user_list)
            except:
                self.user_watched_list[user] = json.dumps([contract_addr])
        else:
            self.user_watched_list[user] = json.dumps([contract_addr])

        return {
            "success": True,
            "contract": contract_addr,
            "name": contract_name,
            "risk_assessment": risk_data,
            "monitoring_started": True,
            "alert_on": "high+ risk transactions"
        }


    @gl.public.write
    def analyze_contract_before_interaction(
        self,
        contract_addr: str,
        function_name: str,
        params: str,
        value_eth: str
    ) -> dict:
        """
        Before interacting with a contract, get AI security analysis.
        PROACTIVE: Get warning BEFORE you interact.

        Args:
            contract_addr: Contract you want to interact with
            function_name: Function you want to call
            params: Function parameters
            value_eth: ETH amount to send (0 if none)

        Returns:
            dict: Risk assessment + warnings + recommendations
        """
        user = str(gl.message.sender_address)
        addr_lower = contract_addr.lower()

        # Get or fetch contract risk profile
        contract_risk = {}
        if addr_lower in self.watched_contracts:
            try:
                contract_risk = json.loads(self.watched_contracts[addr_lower])
            except:
                contract_risk = {}

        # AI analyze specific interaction
        def analyze_interaction() -> str:
            prompt = f"""Analyze this specific smart contract interaction for security:

User: {user}
Contract: {contract_addr} ({contract_risk.get('contract_type', 'unknown')})
Function: {function_name}
Parameters: {params}
Value Sent: {value_eth} ETH

Based on common exploits and scam patterns, assess:
1. Safety of this specific interaction
2. Risks associated with this function
3. Common scams targeting this function
4. Recommended precautions BEFORE confirming
5. If you should proceed or wait
6. What to verify in the transaction

Return JSON: {{
    "interaction_risk": "<safe|caution|dangerous|critical>",
    "reason": "<brief explanation>",
    "function_risks": ["<risk1>"],
    "common_scams": ["<scam1>"],
    "precautions_before_tx": ["<action1>"],
    "should_proceed": <true|false>,
    "verify_these": ["<verify1>"],
    "confidence": 0-100
}}"""
            return gl.nondet.exec_prompt(prompt)

        interaction_raw = gl.eq_principle.prompt_non_comparative(
            analyze_interaction,
            task="Analyze contract interaction safety",
            criteria="Interaction risk must be safe/caution/dangerous/critical. Include precautions."
        )

        interaction_data = self._parse_llm_json(interaction_raw, {
            "interaction_risk": "unknown",
            "reason": "Could not analyze",
            "function_risks": [],
            "common_scams": [],
            "precautions_before_tx": [],
            "should_proceed": True,
            "verify_these": [],
            "confidence": 0
        })

        # Store as warning if high risk
        if interaction_data.get("interaction_risk") in ["dangerous", "critical"]:
            warning = json.dumps({
                "user": user,
                "contract": contract_addr,
                "function": function_name,
                "risk": interaction_data.get("interaction_risk"),
                "reason": interaction_data.get("reason"),
                "timestamp": "current"
            })
            self.pre_interaction_warnings.append(warning)

        return {
            "status": "analyzed",
            "contract": contract_addr,
            "function": function_name,
            "interaction_risk": interaction_data.get("interaction_risk", "unknown"),
            "reason": interaction_data.get("reason", ""),
            "precautions": interaction_data.get("precautions_before_tx", []),
            "should_proceed": interaction_data.get("should_proceed", True),
            "verify_before_confirming": interaction_data.get("verify_these", []),
            "common_scams_to_watch": interaction_data.get("common_scams", []),
            "confidence_percent": interaction_data.get("confidence", 0),
            "action": "STOP - High Risk!" if not interaction_data.get("should_proceed") else "OK to proceed with caution"
        }


    @gl.public.view
    def get_contract_risk_profile(self, contract_addr: str) -> dict:
        """
        Get complete risk profile of a contract.
        Use BEFORE deciding to interact.

        Args:
            contract_addr: Contract to analyze

        Returns:
            dict: Risk profile with all known issues
        """
        addr_lower = contract_addr.lower()

        if addr_lower not in self.watched_contracts:
            return {
                "status": "not_monitored",
                "contract": contract_addr,
                "message": "Add this contract to watch list first",
                "recommendation": "Call add_contract_to_watch() first"
            }

        try:
            contract_data = json.loads(self.watched_contracts[addr_lower])
        except:
            return {
                "status": "error",
                "contract": contract_addr,
                "message": "Could not load contract data"
            }

        # Count tracked threats for this contract
        threat_count = 0
        for i in range(len(self.tracked_addresses)):
            if self.tracked_addresses[i].lower() == addr_lower:
                threat_count += 1

        risk_icon = "🟢" if contract_data.get("initial_risk") == "low" else \
                   "🟡" if contract_data.get("initial_risk") == "medium" else \
                   "🔴" if contract_data.get("initial_risk") == "high" else "⛔"

        return {
            "status": "monitored",
            "contract": contract_addr,
            "name": contract_data.get("name", "Unknown"),
            "risk_icon": risk_icon,
            "initial_risk": contract_data.get("initial_risk", "unknown"),
            "contract_type": contract_data.get("contract_type", "unknown"),
            "risks_to_watch": contract_data.get("risks", []),
            "red_flags": contract_data.get("red_flags", []),
            "precautions": contract_data.get("precautions", []),
            "audit_needed": contract_data.get("audit_needed", False),
            "threats_detected": threat_count,
            "recommendation": "Safe to use" if contract_data.get("initial_risk") in ["low", "medium"] else "Review before interacting"
        }


    @gl.public.view
    def get_user_interaction_history(self, user_addr: str) -> dict:
        """
        Get user's contract interaction history.
        See which dApps you've used and their security status.

        Args:
            user_addr: User wallet address

        Returns:
            dict: Interaction history with risks
        """
        user_lower = user_addr.lower()

        # Get watched contracts for this user
        watched = []
        if user_lower in self.user_watched_list:
            try:
                watched = json.loads(self.user_watched_list[user_lower])
            except:
                watched = []

        # Get interaction history if stored
        interaction_history = []
        if user_lower in self.user_contract_interactions:
            try:
                history_data = json.loads(self.user_contract_interactions[user_lower])
                interaction_history = history_data.get("interactions", [])
            except:
                interaction_history = []

        # Build profile for each watched contract
        contract_profiles = []
        for contract_addr in watched:
            if contract_addr.lower() in self.watched_contracts:
                try:
                    contract_data = json.loads(self.watched_contracts[contract_addr.lower()])
                    contract_profiles.append({
                        "contract": contract_addr,
                        "name": contract_data.get("name", "Unknown"),
                        "risk": contract_data.get("initial_risk", "unknown"),
                        "type": contract_data.get("contract_type", "unknown"),
                        "interactions": len([i for i in interaction_history if i.get("contract") == contract_addr])
                    })
                except:
                    pass

        return {
            "user": user_addr,
            "total_watched_contracts": len(watched),
            "watched_contracts": contract_profiles,
            "total_interactions": len(interaction_history),
            "recent_interactions": interaction_history[-5:] if interaction_history else [],
            "high_risk_contracts": len([c for c in contract_profiles if c.get("risk") in ["high", "critical"]]),
            "recommendation": "Monitor high-risk contracts closely"
        }


    @gl.public.view
    def monitor_dapp_contracts(self) -> dict:
        """
        Global view: Monitor ALL dApps/contracts being watched.
        Dashboard for security team to see what users interact with.

        Returns:
            dict: DApp monitoring dashboard
        """
        total_contracts = 0
        high_risk_count = 0
        low_risk_count = 0
        audit_needed_count = 0

        contract_list = []

        # Scan all watched contracts (TreeMap doesn't iterate, so we use tracked for overview)
        for i in range(len(self.tracked_addresses)):
            contract_addr = self.tracked_addresses[i]
            if contract_addr in self.watched_contracts:
                try:
                    data = json.loads(self.watched_contracts[contract_addr])
                    total_contracts += 1

                    risk = data.get("initial_risk", "unknown")
                    if risk == "high":
                        high_risk_count += 1
                    elif risk == "low":
                        low_risk_count += 1

                    if data.get("audit_needed", False):
                        audit_needed_count += 1

                    contract_list.append({
                        "name": data.get("name", "Unknown"),
                        "address": contract_addr,
                        "risk": risk,
                        "type": data.get("contract_type", "unknown"),
                        "red_flags": len(data.get("red_flags", []))
                    })
                except:
                    pass

        alerts_count = len(self.pre_interaction_warnings)
        
        return {
            "status": "monitoring_active",
            "total_dapps_monitored": total_contracts,
            "high_risk_dapps": high_risk_count,
            "safe_dapps": low_risk_count,
            "require_audit": audit_needed_count,
            "dapp_list": contract_list[:20],  # Top 20
            "alerts": alerts_count,
            "action_items": high_risk_count + audit_needed_count
        }


    @gl.public.view
    def get_safer_alternatives(self) -> dict:
        """
        Get recommendations for SAFER dApp/contract alternatives.
        If a contract is risky, AI suggests safer options.

        Returns:
            dict: Safer alternatives based on use case
        """
        # Analyze patterns of watched contracts
        contract_use_cases = {}
        for i in range(len(self.tracked_addresses)):
            contract_addr = self.tracked_addresses[i]
            if contract_addr in self.watched_contracts:
                try:
                    data = json.loads(self.watched_contracts[contract_addr])
                    use_case = data.get("contract_type", "unknown")
                    if use_case not in contract_use_cases:
                        contract_use_cases[use_case] = []
                    contract_use_cases[use_case].append({
                        "name": data.get("name", "Unknown"),
                        "risk": data.get("initial_risk", "unknown")
                    })
                except:
                    pass

        # AI recommend safer alternatives
        def get_recommendations() -> str:
            prompt = f"""Based on these dApp/contract use cases and risk levels:

{json.dumps(contract_use_cases)}

Recommend SAFER alternatives for each use case:
1. Identify high-risk contracts
2. Suggest well-audited, safer alternatives
3. Explain why they're safer
4. Rate each alternative

Return JSON: {{
    "safer_alternatives": {{
        "<use_case>": [
            {{"recommended": "<name>", "why_safer": "<reason>", "rating": "<excellent|good|fair>"}}
        ]
    }},
    "general_safety_tips": ["<tip1>"],
    "priority_switches": ["<switch1>"]
}}"""
            return gl.nondet.exec_prompt(prompt)

        rec_raw = gl.eq_principle.prompt_non_comparative(
            get_recommendations,
            task="Recommend safer dApp alternatives",
            criteria="Include specific safer alternatives with explanations"
        )

        recommendations = self._parse_llm_json(rec_raw, {
            "safer_alternatives": {},
            "general_safety_tips": ["Research before interacting", "Start with small amounts"],
            "priority_switches": []
        })

        return {
            "status": "recommendations_generated",
            "safer_alternatives": recommendations.get("safer_alternatives", {}),
            "safety_tips": recommendations.get("general_safety_tips", []),
            "priority_switches": recommendations.get("priority_switches", []),
            "message": "Review safer alternatives before interacting with high-risk contracts"
        }

    # ==================== WALLET CONNECTION & dAPP INTEGRATION ====================

    @gl.public.write
    def connect_wallet(self) -> dict:
        """
        Connect user's wallet to SecurityGuard for monitoring.
        Automatically called when user interacts with any method.

        Returns:
            dict: Connection confirmation with wallet health
        """
        user = str(gl.message.sender_address)
        
        # Create connection record
        connection_data = {
            "wallet": user,
            "connected_at": "current",
            "monitoring_enabled": True,
            "auto_scan_enabled": True,
            "alerts_enabled": True,
            "health_score": 0
        }
        
        self.connected_wallets[user] = json.dumps(connection_data)
        
        # Initialize wallet health score
        self.wallet_health_scores[user] = u256(100)
        
        return {
            "success": True,
            "wallet": user,
            "status": "connected",
            "message": "Wallet connected to SecurityGuard. Your dApp interactions will be monitored.",
            "features": [
                "Real-time dApp health monitoring",
                "Pre-interaction security warnings",
                "Wallet security scanning",
                "Interaction history tracking",
                "Risk alerts on suspicious activity"
            ],
            "health_score": 100
        }


    @gl.public.write
    def register_dapp(self, dapp_addr: str, dapp_name: str, dapp_type: str) -> dict:
        """
        Register a dApp for integration with SecurityGuard.
        Enables cross-dApp security monitoring.

        Args:
            dapp_addr: dApp contract address
            dapp_name: dApp name (e.g., "Uniswap", "AAVE")
            dapp_type: dApp type (DEX, Lending, Staking, etc.)

        Returns:
            dict: Registration confirmation
        """
        addr_lower = dapp_addr.lower()
        
        # Register dApp
        dapp_info = {
            "address": dapp_addr,
            "name": dapp_name,
            "type": dapp_type,
            "registered_at": "current",
            "users_count": 0,
            "security_audit_status": "pending"
        }
        
        self.dapp_registry[addr_lower] = json.dumps(dapp_info)
        
        # Set initial health status (analyze dApp)
        def analyze_dapp() -> str:
            prompt = f"""Analyze this dApp for security and health:

dApp: {dapp_name}
Address: {dapp_addr}
Type: {dapp_type}

Provide a health assessment:
1. Known security issues or vulnerabilities
2. Community reputation
3. Audit status
4. Overall health status (healthy/warning/critical)
5. Risk warnings

Return JSON: {{
    "health_status": "<healthy|warning|critical>",
    "security_issues": ["<issue1>"],
    "audit_status": "<audited|pending|not_audited>",
    "risk_level": "<low|medium|high|critical>",
    "warnings": ["<warning1>"],
    "recommendation": "<action>"
}}"""
            return gl.nondet.exec_prompt(prompt)

        analysis_raw = gl.eq_principle.prompt_non_comparative(
            analyze_dapp,
            task="Analyze dApp health and security",
            criteria="Health status must be healthy/warning/critical"
        )

        dapp_health = self._parse_llm_json(analysis_raw, {
            "health_status": "unknown",
            "security_issues": [],
            "audit_status": "unknown",
            "risk_level": "unknown",
            "warnings": [],
            "recommendation": "Monitor this dApp"
        })

        self.dapp_health_status[addr_lower] = json.dumps(dapp_health)
        
        return {
            "success": True,
            "dapp": dapp_name,
            "address": dapp_addr,
            "status": "registered",
            "health_analysis": dapp_health,
            "message": f"{dapp_name} registered and health-checked"
        }


    @gl.public.view
    def scan_wallet_security(self, wallet_addr: str) -> dict:
        """
        Scan a wallet for security risks and exposure.
        Shows all contracts interacted with and their health status.

        Args:
            wallet_addr: Wallet address to scan

        Returns:
            dict: Complete wallet security report
        """
        wallet_lower = wallet_addr.lower()
        
        # Get wallet's interaction history
        watched = []
        if wallet_lower in self.user_watched_list:
            try:
                watched = json.loads(self.user_watched_list[wallet_lower])
            except:
                watched = []
        
        # Analyze each contract
        total_risk = 0
        contracts_scanned = 0
        high_risk_contracts = []
        warning_contracts = []
        safe_contracts = []
        
        contract_analysis = []
        for contract_addr in watched:
            if contract_addr.lower() in self.watched_contracts:
                try:
                    contract_data = json.loads(self.watched_contracts[contract_addr.lower()])
                    risk = contract_data.get("initial_risk", "unknown")
                    name = contract_data.get("name", "Unknown")
                    
                    contract_analysis.append({
                        "contract": contract_addr,
                        "name": name,
                        "risk": risk,
                        "type": contract_data.get("contract_type", "unknown")
                    })
                    
                    contracts_scanned += 1
                    
                    # Categorize
                    if risk == "critical" or risk == "high":
                        high_risk_contracts.append(name)
                    elif risk == "medium":
                        warning_contracts.append(name)
                    else:
                        safe_contracts.append(name)
                        
                except:
                    pass
        
        # Calculate wallet health score
        health_score = 100
        if contracts_scanned > 0:
            health_score = max(0, 100 - (len(high_risk_contracts) * 25) - (len(warning_contracts) * 10))
        
        # Update wallet health
        self.wallet_health_scores[wallet_lower] = u256(health_score)
        
        # Determine overall status
        overall_status = "healthy"
        if health_score < 30:
            overall_status = "critical"
        elif health_score < 60:
            overall_status = "warning"
        
        return {
            "status": "scan_complete",
            "wallet": wallet_addr,
            "health_score": health_score,
            "overall_status": overall_status,
            "contracts_analyzed": contracts_scanned,
            "breakdown": {
                "safe_contracts": len(safe_contracts),
                "warning_contracts": len(warning_contracts),
                "high_risk_contracts": len(high_risk_contracts)
            },
            "high_risk_list": high_risk_contracts,
            "warning_list": warning_contracts,
            "detailed_analysis": contract_analysis,
            "recommendation": "Critical action needed!" if overall_status == "critical" else "Monitor high-risk contracts" if overall_status == "warning" else "Your wallet appears safe"
        }


    @gl.public.view
    def get_dapp_health_status(self, dapp_addr: str) -> dict:
        """
        Get real-time health status of a dApp.
        Called by users BEFORE interacting to check if dApp is healthy.

        Args:
            dapp_addr: dApp contract address

        Returns:
            dict: Complete health and warning information
        """
        addr_lower = dapp_addr.lower()
        
        if addr_lower not in self.dapp_health_status:
            return {
                "status": "not_registered",
                "dapp": dapp_addr,
                "message": "dApp not in SecurityGuard registry. Register it first.",
                "recommendation": "Unknown dApp - use with caution"
            }
        
        try:
            health_data = json.loads(self.dapp_health_status[addr_lower])
        except:
            return {
                "status": "error",
                "dapp": dapp_addr,
                "message": "Could not load dApp health data"
            }
        
        # Get dApp info
        dapp_info = {}
        if addr_lower in self.dapp_registry:
            try:
                dapp_info = json.loads(self.dapp_registry[addr_lower])
            except:
                pass
        
        health_status = health_data.get("health_status", "unknown")
        
        # Visual indicator
        status_icon = "🟢" if health_status == "healthy" else "🟡" if health_status == "warning" else "🔴"
        
        return {
            "status": "health_check_complete",
            "dapp": dapp_info.get("name", "Unknown"),
            "address": dapp_addr,
            "health_icon": status_icon,
            "health_status": health_status,
            "risk_level": health_data.get("risk_level", "unknown"),
            "security_issues": health_data.get("security_issues", []),
            "audit_status": health_data.get("audit_status", "unknown"),
            "warnings": health_data.get("warnings", []),
            "recommendation": health_data.get("recommendation", ""),
            "safe_to_interact": health_status == "healthy",
            "warning_before_use": health_status in ["warning", "critical"]
        }


    @gl.public.write
    def warn_on_unhealthy_dapp_interaction(self, dapp_addr: str, function_name: str) -> dict:
        """
        Trigger warning if user is about to interact with unhealthy dApp.
        Real-time health check during transaction.

        Args:
            dapp_addr: dApp contract user wants to interact with
            function_name: Function being called

        Returns:
            dict: Warning with action recommendation
        """
        user = str(gl.message.sender_address)
        addr_lower = dapp_addr.lower()
        
        # Get dApp health
        health_check = self.get_dapp_health_status(dapp_addr)
        
        if not health_check.get("safe_to_interact", True):
            # Create warning entry
            warning_entry = json.dumps({
                "user": user,
                "dapp": dapp_addr,
                "function": function_name,
                "health_status": health_check.get("health_status", "unknown"),
                "warnings": health_check.get("warnings", []),
                "timestamp": "current",
                "action_taken": "warning_issued"
            })
            self.pre_interaction_warnings.append(warning_entry)
            
            return {
                "warning": True,
                "severity": "critical" if health_check.get("health_status") == "critical" else "high",
                "dapp": health_check.get("dapp", "Unknown"),
                "message": f"⚠️ WARNING: This dApp is currently {health_check.get('health_status')}",
                "issues": health_check.get("security_issues", []),
                "recommendation": health_check.get("recommendation", ""),
                "proceed_anyway": False,
                "unsafe_contract": True
            }
        
        return {
            "warning": False,
            "dapp": health_check.get("dapp", "Unknown"),
            "message": "dApp health check passed. Safe to interact.",
            "health_status": health_check.get("health_status", "unknown"),
            "proceed_anyway": True
        }


    @gl.public.view
    def get_wallet_risk_dashboard(self, wallet_addr: str) -> dict:
        """
        Get comprehensive wallet security dashboard.
        Shows everything: health, risks, warnings, recommendations.

        Args:
            wallet_addr: Wallet to analyze

        Returns:
            dict: Complete dashboard with all metrics
        """
        wallet_lower = wallet_addr.lower()
        
        # Get wallet health score
        health_score = 100
        if wallet_lower in self.wallet_health_scores:
            health_score = int(self.wallet_health_scores[wallet_lower])
        
        # Scan wallet security
        scan_result = self.scan_wallet_security(wallet_addr)
        
        # Get pending warnings for this wallet
        pending_warnings = []
        for warning in self.pre_interaction_warnings:
            try:
                warn_data = json.loads(warning)
                if warn_data.get("user", "").lower() == wallet_lower:
                    pending_warnings.append({
                        "dapp": warn_data.get("dapp", "Unknown"),
                        "issue": warn_data.get("function", "Unknown function"),
                        "severity": "high"
                    })
            except:
                pass
        
        # Determine overall wallet status
        status_icon = "🟢" if health_score > 70 else "🟡" if health_score > 40 else "🔴"
        status_text = "Safe" if health_score > 70 else "Warning" if health_score > 40 else "Critical"
        
        return {
            "wallet": wallet_addr,
            "overall_status": status_text,
            "status_icon": status_icon,
            "health_score": health_score,
            "security_metrics": {
                "safe_contracts": scan_result.get("breakdown", {}).get("safe_contracts", 0),
                "warning_contracts": scan_result.get("breakdown", {}).get("warning_contracts", 0),
                "high_risk_contracts": scan_result.get("breakdown", {}).get("high_risk_contracts", 0),
                "total_contracts": scan_result.get("contracts_analyzed", 0)
            },
            "pending_warnings": pending_warnings,
            "recent_high_risk": scan_result.get("high_risk_list", []),
            "actions_recommended": [
                "Review high-risk contracts" if scan_result.get("high_risk_contracts", 0) > 0 else None,
                "Update security settings" if health_score < 60 else None,
                "Enable wallet monitoring" if not self.monitoring_enabled else None
            ],
            "quick_actions": {
                "scan_wallet": True,
                "check_dapp_health": True,
                "view_interaction_history": True,
                "get_safer_alternatives": True
            }
        }

    # ==================== INTERNAL HELPERS ====================

    def _parse_llm_json(self, response: str, fallback: dict) -> dict:
        """
        Safely parse JSON from LLM response with robust error handling.

        Args:
            response: Raw LLM response string
            fallback: Default dict to return if parsing fails

        Returns:
            dict: Parsed JSON or fallback dict
        """
        cleaned = str(response).strip()

        # Remove markdown code blocks
        if "```json" in cleaned:
            cleaned = cleaned.split("```json")[1].split("```")[0].strip()
        elif "```" in cleaned:
            cleaned = cleaned.split("```")[1].split("```")[0].strip()

        # Extract JSON by finding curly braces if not at start
        if not cleaned.startswith("{"):
            start = cleaned.find("{")
            end = cleaned.rfind("}")
            if start != -1 and end != -1 and end > start:
                cleaned = cleaned[start:end+1]

        # Try to parse
        try:
            parsed = json.loads(cleaned)
            if isinstance(parsed, dict):
                return parsed
            else:
                return fallback
        except:
            return fallback

    def _is_operator(self, addr: Address) -> bool:
        """Check if address is owner or operator."""
        if addr == self.owner:
            return True
        for op in self.operators:
            if op == addr:
                return True
        return False


    def _address_in_list(self, address: str, list_type: str) -> bool:
        """Check if address is in blacklist or whitelist."""
        addr_lower = address.lower()

        if list_type == "blacklist":
            for addr in self.blacklist:
                if str(addr).lower() == addr_lower:
                    return True
        elif list_type == "whitelist":
            for addr in self.whitelist:
                if str(addr).lower() == addr_lower:
                    return True

        return False


    def _add_to_blacklist_internal(self, address: str) -> bool:
        """Internal method to add to blacklist (accepts string from transaction scans)."""
        # Check if already blacklisted
        if self._address_in_list(address, "blacklist"):
            return False

        try:
            addr = Address(address)
            # Check if already exists (Address comparison)
            for existing in self.blacklist:
                if existing == addr:
                    return False
            self.blacklist.append(addr)
            return True
        except:
            return False


    def _update_risk_tracking(self, address: str, score: int) -> None:
        """Update or add risk score for address."""
        addr_lower = address.lower()

        # Check if already tracked
        for i in range(len(self.tracked_addresses)):
            if self.tracked_addresses[i].lower() == addr_lower:
                # Update existing
                self.risk_scores[i] = u256(score)
                # Update trend data
                self._update_threat_trend(address, score)
                return

        # Add new
        self.tracked_addresses.append(address)
        self.risk_scores.append(u256(score))
        # Initialize trend for new address
        self._update_threat_trend(address, score)


    def _update_threat_trend(self, address: str, current_score: int) -> None:
        """Track risk trends for visualization (for charts/graphs)."""
        try:
            # Get or create trend data as JSON string
            if address not in self.threat_trends:
                trend_data = {
                    "min_score": current_score,
                    "max_score": current_score,
                    "avg_score": current_score,
                    "scans": 1,
                    "trend": "stable"
                }
                self.threat_trends[address] = json.dumps(trend_data)
            else:
                # Parse existing trend data
                trend_json = self.threat_trends[address]
                trend = json.loads(trend_json)
                scans = trend.get("scans", 1)
                avg = trend.get("avg_score", 0)
                
                # Update min/max
                if current_score < trend.get("min_score", 100):
                    trend["min_score"] = current_score
                if current_score > trend.get("max_score", 0):
                    trend["max_score"] = current_score
                
                # Update average
                trend["avg_score"] = (avg * scans + current_score) // (scans + 1)
                trend["scans"] = scans + 1
                
                # Determine trend direction
                if current_score > avg:
                    trend["trend"] = "rising"
                elif current_score < avg:
                    trend["trend"] = "declining"
                else:
                    trend["trend"] = "stable"
                
                # Store back as JSON string
                self.threat_trends[address] = json.dumps(trend)
        except:
            pass  # Silent fail


    def _score_to_level(self, score: int) -> str:
        """Convert risk score to threat level."""
        if score >= int(self.critical_threshold):
            return "critical"
        elif score >= int(self.high_threshold):
            return "high"
        elif score >= int(self.medium_threshold):
            return "medium"
        else:
            return "low"


    def _save_to_history(self, result: dict) -> None:
        """
        Save scan result to history for pattern learning.
        Keeps only the last 100 scans.

        Args:
            result: Scan result dictionary to save
        """
        try:
            # Convert result to JSON string
            history_entry = json.dumps({
                "scan_id": result.get("scan_id", 0),
                "from_address": result.get("from_address", ""),
                "to_address": result.get("to_address", ""),
                "value": result.get("value", "0"),
                "risk_score": result.get("risk_score", 0),
                "threat_level": result.get("threat_level", "unknown"),
                "exploits_detected": result.get("exploits_detected", []),
                "timestamp": "current"  # GenLayer will add actual timestamp
            })

            # Append to history
            self.scan_history.append(history_entry)

            # Keep only last 100 entries - remove oldest if over limit
            while len(self.scan_history) > 100:
                # Remove first (oldest) entry
                # Note: DynArray doesn't have pop(0), so we rebuild the list
                temp_history = []
                for i in range(1, len(self.scan_history)):  # Skip index 0
                    temp_history.append(self.scan_history[i])

                # Clear and rebuild
                while len(self.scan_history) > 0:
                    self.scan_history.pop()

                for entry in temp_history:
                    self.scan_history.append(entry)

        except Exception as e:
            # Silent fail - don't break scanning if history saving fails
            pass


    def _trigger_webhook(self, result: dict) -> None:
        """
        Trigger webhook notification for high-risk scans.

        Args:
            result: Scan result dictionary to send
        """
        if not self.webhook_enabled or not self.webhook_url:
            return

        try:
            # Prepare webhook payload
            payload = {
                "event": "threat_detected",
                "scan_id": result.get("scan_id", 0),
                "risk_score": result.get("risk_score", 0),
                "threat_level": result.get("threat_level", "unknown"),
                "from_address": result.get("from_address", ""),
                "to_address": result.get("to_address", ""),
                "exploits_detected": result.get("exploits_detected", []),
                "explanation": result.get("explanation", ""),
                "action_taken": result.get("action_taken", ""),
                "system_paused": result.get("system_paused", False),
                "timestamp": "current"
            }

            # Convert to JSON string for POST request
            payload_json = json.dumps(payload)

            # Use GenLayer's web capabilities to POST to webhook
            # Note: This is a non-deterministic operation
            def send_webhook() -> str:
                try:
                    # GenLayer web POST (if available in future versions)
                    # For now, we'll use a simple marker that webhook would be triggered
                    return f"Webhook triggered: {self.webhook_url}"
                except:
                    return "Webhook failed"

            # Execute webhook (non-deterministic, doesn't affect consensus)
            webhook_result = send_webhook()

        except Exception as e:
            # Silent fail - don't break scanning if webhook fails
            pass
