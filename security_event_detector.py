from dataclasses import dataclass
from enum import Enum
from datetime import datetime
from typing import List, Optional


class SeverityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(Enum):
    FAILED_LOGIN_ATTEMPTS = "multiple_failed_logins"
    SUCCESSFUL_LOGIN_AFTER_FAILURES = "successful_login_after_failures"
    NEW_USER_CREATION = "new_user_creation"
    SUSPICIOUS_POWERSHELL = "suspicious_powershell_activity"


@dataclass
class SecurityEvent:
    event_type: EventType
    severity: SeverityLevel
    timestamp: datetime
    user: str
    details: str
    mitre_technique: Optional[str] = None
    recommended_action: Optional[str] = None


class EventDetector:
    """Detects security events in log files."""

    def __init__(self):
        self.failed_login_threshold = 3

    def parse_timestamp(self, timestamp_text: str) -> datetime:
        """Safely convert a timestamp string into a datetime object."""
        try:
            return datetime.fromisoformat(timestamp_text)
        except (TypeError, ValueError):
            return datetime.now()

    def detect_failed_logins(self, logs: dict) -> List[SecurityEvent]:
        """Detect multiple failed login attempts."""
        detected_events = []
        failed_attempts = {}

        for log_entry in logs.get("login_attempts", []):
            if log_entry.get("status") == "failed":
                user = log_entry.get("user", "unknown")
                src_ip = log_entry.get("src_ip", "unknown")

                key = (user, src_ip)
                failed_attempts[key] = failed_attempts.get(key, 0) + 1

        for (user, src_ip), count in failed_attempts.items():
            if count >= self.failed_login_threshold:
                event = SecurityEvent(
                    event_type=EventType.FAILED_LOGIN_ATTEMPTS,
                    severity=SeverityLevel.MEDIUM,
                    timestamp=datetime.now(),
                    user=user,
                    details=f"User {user} had {count} failed login attempts from {src_ip}.",
                    mitre_technique="T1110 - Brute Force",
                    recommended_action="Review the account and source IP. Consider password reset, MFA, and account lockout policies."
                )
                detected_events.append(event)

        return detected_events

    def detect_successful_login_after_failures(self, logs: dict) -> List[SecurityEvent]:
        """Detect successful login following several failed attempts."""
        detected_events = []
        failed_attempts = {}

        for log_entry in logs.get("login_attempts", []):
            user = log_entry.get("user", "unknown")
            src_ip = log_entry.get("src_ip", "unknown")
            key = (user, src_ip)

            if log_entry.get("status") == "failed":
                failed_attempts[key] = failed_attempts.get(key, 0) + 1

            elif log_entry.get("status") == "success":
                if failed_attempts.get(key, 0) >= self.failed_login_threshold:
                    event = SecurityEvent(
                        event_type=EventType.SUCCESSFUL_LOGIN_AFTER_FAILURES,
                        severity=SeverityLevel.HIGH,
                        timestamp=self.parse_timestamp(log_entry.get("timestamp")),
                        user=user,
                        details=f"Successful login for {user} from {src_ip} after {failed_attempts[key]} failed attempts.",
                        mitre_technique="T1078 - Valid Accounts",
                        recommended_action="Investigate whether the login was authorized. Reset credentials if compromise is suspected."
                    )
                    detected_events.append(event)

                failed_attempts[key] = 0

        return detected_events

    def detect_new_user_creation(self, logs: dict) -> List[SecurityEvent]:
        """Detect new user account creation."""
        detected_events = []

        for log_entry in logs.get("user_events", []):
            if log_entry.get("action") == "created":
                created_user = log_entry.get("created_user", "unknown")
                admin_user = log_entry.get("user", "unknown")

                event = SecurityEvent(
                    event_type=EventType.NEW_USER_CREATION,
                    severity=SeverityLevel.MEDIUM,
                    timestamp=self.parse_timestamp(log_entry.get("timestamp")),
                    user=admin_user,
                    details=f"New user account created: {created_user} by {admin_user}.",
                    mitre_technique="T1136.001 - Create Account: Local Account",
                    recommended_action="Verify that the new account was approved. Disable or remove unauthorized accounts."
                )
                detected_events.append(event)

        return detected_events

    def detect_suspicious_powershell(self, logs: dict) -> List[SecurityEvent]:
        """Detect suspicious PowerShell or command-line activity."""
        detected_events = []

        suspicious_keywords = [
            "-enc",
            "-encodedcommand",
            "bypass",
            "hidden",
            "downloadstring",
            "invoke-webrequest",
            "iex"
        ]

        for log_entry in logs.get("command_executions", []):
            command = log_entry.get("command", "").lower()
            process = log_entry.get("process", "").lower()

            if "powershell" in process and any(keyword in command for keyword in suspicious_keywords):
                event = SecurityEvent(
                    event_type=EventType.SUSPICIOUS_POWERSHELL,
                    severity=SeverityLevel.HIGH,
                    timestamp=self.parse_timestamp(log_entry.get("timestamp")),
                    user=log_entry.get("user", "unknown"),
                    details=f"Suspicious PowerShell command detected: {log_entry.get('command')}",
                    mitre_technique="T1059.001 - PowerShell",
                    recommended_action="Review the PowerShell command, user, parent process, and host for possible malicious activity."
                )
                detected_events.append(event)

        return detected_events

    def run_all_detections(self, logs: dict) -> List[SecurityEvent]:
        """Run all detection rules."""
        all_events = []

        all_events.extend(self.detect_failed_logins(logs))
        all_events.extend(self.detect_successful_login_after_failures(logs))
        all_events.extend(self.detect_new_user_creation(logs))
        all_events.extend(self.detect_suspicious_powershell(logs))

        return all_events
if __name__ == "__main__":
    sample_logs = {
        "login_attempts": [
            {
                "timestamp": "2026-06-20T10:00:00",
                "user": "jsmith",
                "src_ip": "192.168.1.50",
                "status": "failed"
            },
            {
                "timestamp": "2026-06-20T10:01:00",
                "user": "jsmith",
                "src_ip": "192.168.1.50",
                "status": "failed"
            },
            {
                "timestamp": "2026-06-20T10:02:00",
                "user": "jsmith",
                "src_ip": "192.168.1.50",
                "status": "failed"
            },
            {
                "timestamp": "2026-06-20T10:03:00",
                "user": "jsmith",
                "src_ip": "192.168.1.50",
                "status": "success"
            }
        ],

        "user_events": [
            {
                "timestamp": "2026-06-20T11:00:00",
                "user": "admin",
                "action": "created",
                "created_user": "newuser1"
            }
        ],

        "command_executions": [
            {
                "timestamp": "2026-06-20T12:00:00",
                "user": "jsmith",
                "process": "powershell.exe",
                "command": "powershell.exe -enc aW52b2tlLXdlYnJlcXVlc3Q="
            }
        ]
    }

    detector = EventDetector()
    events = detector.run_all_detections(sample_logs)

    print("Security Events Detected:")
    print("-" * 40)

    for event in events:
        print(f"Event Type: {event.event_type.value}")
        print(f"Severity: {event.severity.value}")
        print(f"Timestamp: {event.timestamp}")
        print(f"User: {event.user}")
        print(f"Details: {event.details}")
        print(f"MITRE Technique: {event.mitre_technique}")
        print(f"Recommended Action: {event.recommended_action}")
        print("-" * 40)
