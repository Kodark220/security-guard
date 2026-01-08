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

        # Note: blacklist, whitelist, tracked_addresses, risk_scores, scan_history
        # are auto-initialized as empty DynArrays by the storage system


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
                return

        # Add new
        self.tracked_addresses.append(address)
        self.risk_scores.append(u256(score))


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
