"""
APKVoid — Permission risk database and scoring engine.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    SAFE     = "SAFE"


RISK_SCORES = {
    RiskLevel.CRITICAL: 100,
    RiskLevel.HIGH:     60,
    RiskLevel.MEDIUM:   25,
    RiskLevel.LOW:      10,
    RiskLevel.SAFE:     0,
}


@dataclass
class PermissionInfo:
    name: str
    risk: RiskLevel
    category: str
    description: str
    malware_indicator: bool = False


# Full Android permission database with risk ratings
PERMISSION_DB: dict[str, PermissionInfo] = {
    # ── CRITICAL ──────────────────────────────────────────────────
    "android.permission.SEND_SMS": PermissionInfo(
        "SEND_SMS", RiskLevel.CRITICAL, "Messaging",
        "Send SMS messages — used by SMS trojans to rack up charges or exfiltrate 2FA codes.",
        malware_indicator=True,
    ),
    "android.permission.RECEIVE_SMS": PermissionInfo(
        "RECEIVE_SMS", RiskLevel.CRITICAL, "Messaging",
        "Intercept incoming SMS — core technique for stealing OTP/2FA tokens.",
        malware_indicator=True,
    ),
    "android.permission.READ_SMS": PermissionInfo(
        "READ_SMS", RiskLevel.CRITICAL, "Messaging",
        "Read all SMS messages — banking trojans use this to steal authentication codes.",
        malware_indicator=True,
    ),
    "android.permission.RECEIVE_MMS": PermissionInfo(
        "RECEIVE_MMS", RiskLevel.CRITICAL, "Messaging",
        "Intercept MMS — used in stagefright-style exploits.",
        malware_indicator=True,
    ),
    "android.permission.BIND_DEVICE_ADMIN": PermissionInfo(
        "BIND_DEVICE_ADMIN", RiskLevel.CRITICAL, "Device Control",
        "Device administrator privileges — ransomware and stalkerware use this to lock devices.",
        malware_indicator=True,
    ),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": PermissionInfo(
        "BIND_ACCESSIBILITY_SERVICE", RiskLevel.CRITICAL, "Accessibility",
        "Full UI interaction — banking trojans abuse this to overlay login screens and steal credentials.",
        malware_indicator=True,
    ),
    "android.permission.INSTALL_PACKAGES": PermissionInfo(
        "INSTALL_PACKAGES", RiskLevel.CRITICAL, "Package Management",
        "Install additional APKs without user interaction — dropper malware signature.",
        malware_indicator=True,
    ),
    "android.permission.DELETE_PACKAGES": PermissionInfo(
        "DELETE_PACKAGES", RiskLevel.CRITICAL, "Package Management",
        "Silently uninstall apps — used to remove security software.",
        malware_indicator=True,
    ),
    "android.permission.CHANGE_COMPONENT_ENABLED_STATE": PermissionInfo(
        "CHANGE_COMPONENT_ENABLED_STATE", RiskLevel.CRITICAL, "System",
        "Hide/show app components — rootkit technique for persistence.",
        malware_indicator=True,
    ),
    "android.permission.MASTER_CLEAR": PermissionInfo(
        "MASTER_CLEAR", RiskLevel.CRITICAL, "Device Control",
        "Factory reset the device — destructive malware capability.",
        malware_indicator=True,
    ),

    # ── HIGH ──────────────────────────────────────────────────────
    "android.permission.READ_CONTACTS": PermissionInfo(
        "READ_CONTACTS", RiskLevel.HIGH, "Personal Data",
        "Access entire contacts list — used for data harvesting and spam propagation.",
    ),
    "android.permission.WRITE_CONTACTS": PermissionInfo(
        "WRITE_CONTACTS", RiskLevel.HIGH, "Personal Data",
        "Modify contacts — adware uses this to inject entries.",
    ),
    "android.permission.ACCESS_FINE_LOCATION": PermissionInfo(
        "ACCESS_FINE_LOCATION", RiskLevel.HIGH, "Location",
        "Precise GPS location — stalkerware and adware track users silently.",
        malware_indicator=True,
    ),
    "android.permission.ACCESS_BACKGROUND_LOCATION": PermissionInfo(
        "ACCESS_BACKGROUND_LOCATION", RiskLevel.HIGH, "Location",
        "Location access while app is in background — major stalkerware indicator.",
        malware_indicator=True,
    ),
    "android.permission.RECORD_AUDIO": PermissionInfo(
        "RECORD_AUDIO", RiskLevel.HIGH, "Surveillance",
        "Microphone access — spyware records calls and ambient audio.",
        malware_indicator=True,
    ),
    "android.permission.CAMERA": PermissionInfo(
        "CAMERA", RiskLevel.HIGH, "Surveillance",
        "Camera access — spyware takes photos/video without user knowledge.",
    ),
    "android.permission.READ_CALL_LOG": PermissionInfo(
        "READ_CALL_LOG", RiskLevel.HIGH, "Personal Data",
        "Access call history — surveillance and data-harvesting tool.",
        malware_indicator=True,
    ),
    "android.permission.PROCESS_OUTGOING_CALLS": PermissionInfo(
        "PROCESS_OUTGOING_CALLS", RiskLevel.HIGH, "Telephony",
        "Intercept and reroute phone calls — call-fraud malware.",
        malware_indicator=True,
    ),
    "android.permission.READ_PHONE_STATE": PermissionInfo(
        "READ_PHONE_STATE", RiskLevel.HIGH, "Device ID",
        "Read IMEI, SIM, call state — device fingerprinting for tracking.",
    ),
    "android.permission.USE_BIOMETRIC": PermissionInfo(
        "USE_BIOMETRIC", RiskLevel.HIGH, "Authentication",
        "Biometric authentication access — credential theft attack surface.",
    ),
    "android.permission.USE_FINGERPRINT": PermissionInfo(
        "USE_FINGERPRINT", RiskLevel.HIGH, "Authentication",
        "Fingerprint sensor access — legacy biometric attack surface.",
    ),
    "android.permission.WRITE_SETTINGS": PermissionInfo(
        "WRITE_SETTINGS", RiskLevel.HIGH, "System",
        "Modify system settings — used to disable security features.",
        malware_indicator=True,
    ),
    "android.permission.SYSTEM_ALERT_WINDOW": PermissionInfo(
        "SYSTEM_ALERT_WINDOW", RiskLevel.HIGH, "UI Overlay",
        "Draw over other apps — phishing overlay technique used by banking trojans.",
        malware_indicator=True,
    ),
    "android.permission.GET_ACCOUNTS": PermissionInfo(
        "GET_ACCOUNTS", RiskLevel.HIGH, "Account Data",
        "List all accounts on device — account enumeration for credential attacks.",
    ),
    "android.permission.MANAGE_ACCOUNTS": PermissionInfo(
        "MANAGE_ACCOUNTS", RiskLevel.HIGH, "Account Data",
        "Add/remove/modify accounts — account hijacking capability.",
        malware_indicator=True,
    ),
    "android.permission.READ_EXTERNAL_STORAGE": PermissionInfo(
        "READ_EXTERNAL_STORAGE", RiskLevel.HIGH, "Storage",
        "Read all files on SD card — data exfiltration vector.",
    ),

    # ── MEDIUM ────────────────────────────────────────────────────
    "android.permission.INTERNET": PermissionInfo(
        "INTERNET", RiskLevel.MEDIUM, "Network",
        "Network access — required for C2 communication. Alone harmless, critical in combination.",
    ),
    "android.permission.RECEIVE_BOOT_COMPLETED": PermissionInfo(
        "RECEIVE_BOOT_COMPLETED", RiskLevel.MEDIUM, "Persistence",
        "Start on device boot — persistence mechanism.",
    ),
    "android.permission.WRITE_EXTERNAL_STORAGE": PermissionInfo(
        "WRITE_EXTERNAL_STORAGE", RiskLevel.MEDIUM, "Storage",
        "Write files to SD card — data staging for exfiltration.",
    ),
    "android.permission.ACCESS_WIFI_STATE": PermissionInfo(
        "ACCESS_WIFI_STATE", RiskLevel.MEDIUM, "Network",
        "Wi-Fi network details — network fingerprinting.",
    ),
    "android.permission.CHANGE_WIFI_STATE": PermissionInfo(
        "CHANGE_WIFI_STATE", RiskLevel.MEDIUM, "Network",
        "Control Wi-Fi — can be used to force connections to rogue APs.",
    ),
    "android.permission.BLUETOOTH": PermissionInfo(
        "BLUETOOTH", RiskLevel.MEDIUM, "Connectivity",
        "Bluetooth access — proximity tracking.",
    ),
    "android.permission.NFC": PermissionInfo(
        "NFC", RiskLevel.MEDIUM, "Connectivity",
        "NFC access — payment relay attacks.",
    ),
    "android.permission.REQUEST_INSTALL_PACKAGES": PermissionInfo(
        "REQUEST_INSTALL_PACKAGES", RiskLevel.MEDIUM, "Package Management",
        "Request to install packages — dropper capability.",
    ),
    "android.permission.FOREGROUND_SERVICE": PermissionInfo(
        "FOREGROUND_SERVICE", RiskLevel.MEDIUM, "Persistence",
        "Run foreground service — keeps malware alive in background.",
    ),
    "android.permission.WAKE_LOCK": PermissionInfo(
        "WAKE_LOCK", RiskLevel.MEDIUM, "Power",
        "Prevent device sleep — cryptominer and spyware keep CPU active.",
    ),
    "android.permission.VIBRATE": PermissionInfo(
        "VIBRATE", RiskLevel.LOW, "Hardware",
        "Vibrate motor access — generally benign.",
    ),

    # ── LOW / SAFE ────────────────────────────────────────────────
    "android.permission.ACCESS_NETWORK_STATE": PermissionInfo(
        "ACCESS_NETWORK_STATE", RiskLevel.LOW, "Network",
        "Check if network is available — mostly benign.",
    ),
    "android.permission.FLASHLIGHT": PermissionInfo(
        "FLASHLIGHT", RiskLevel.SAFE, "Hardware",
        "Camera flashlight — benign.",
    ),
    "android.permission.SET_ALARM": PermissionInfo(
        "SET_ALARM", RiskLevel.SAFE, "App",
        "Set alarms — benign.",
    ),
}


def score_permissions(permissions: list[str]) -> tuple[int, list[PermissionInfo]]:
    """Return (total_risk_score, list_of_matched_PermissionInfo)."""
    matched: list[PermissionInfo] = []
    total = 0
    for perm in permissions:
        info = PERMISSION_DB.get(perm)
        if info:
            matched.append(info)
            total += RISK_SCORES[info.risk]
        else:
            # Unknown permission — assign LOW by default
            matched.append(PermissionInfo(
                name=perm.split(".")[-1],
                risk=RiskLevel.LOW,
                category="Unknown",
                description="Unknown permission — not in database.",
            ))
            total += RISK_SCORES[RiskLevel.LOW]
    return total, matched
