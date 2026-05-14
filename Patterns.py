"""
APKVoid — Suspicious API call and string pattern database.
Each pattern maps to a threat category, severity, and description.
"""

from dataclasses import dataclass, field
from enum import Enum


class ThreatCategory(str, Enum):
    DYNAMIC_CODE      = "Dynamic Code Loading"
    REFLECTION        = "Java Reflection"
    NATIVE_CODE       = "Native Code Execution"
    CRYPTO            = "Cryptography"
    NETWORK           = "Network / C2"
    PERSISTENCE       = "Persistence"
    PRIVILEGE_ESC     = "Privilege Escalation"
    DATA_EXFIL        = "Data Exfiltration"
    SURVEILLANCE      = "Surveillance"
    OBFUSCATION       = "Obfuscation"
    SMS_FRAUD         = "SMS Fraud"
    RANSOMWARE        = "Ransomware"
    ANTI_ANALYSIS     = "Anti-Analysis"
    ACCESSIBILITY_ABU = "Accessibility Abuse"


@dataclass
class CodePattern:
    pattern: str
    category: ThreatCategory
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW
    score: int
    description: str
    tags: list[str] = field(default_factory=list)


# ── DEX / Smali API patterns ──────────────────────────────────────
DEX_PATTERNS: list[CodePattern] = [
    # Dynamic Code Loading
    CodePattern(
        "DexClassLoader", ThreatCategory.DYNAMIC_CODE, "CRITICAL", 90,
        "Loads DEX/JAR at runtime from arbitrary path — dropper/plugin malware signature.",
        tags=["dropper", "plugin"],
    ),
    CodePattern(
        "PathClassLoader", ThreatCategory.DYNAMIC_CODE, "HIGH", 50,
        "Runtime class loading from path — potential dynamic payload delivery.",
    ),
    CodePattern(
        "dalvik.system.BaseDexClassLoader", ThreatCategory.DYNAMIC_CODE, "HIGH", 50,
        "Base class for runtime DEX loading — inspect loaded path.",
    ),
    CodePattern(
        "InMemoryDexClassLoader", ThreatCategory.DYNAMIC_CODE, "CRITICAL", 95,
        "Loads DEX directly from memory buffer — advanced in-memory malware execution.",
        tags=["fileless", "advanced"],
    ),
    CodePattern(
        "loadClass", ThreatCategory.DYNAMIC_CODE, "MEDIUM", 20,
        "Dynamic class loading — context-dependent; dangerous when combined with network.",
    ),

    # Reflection
    CodePattern(
        "java.lang.reflect.Method", ThreatCategory.REFLECTION, "HIGH", 45,
        "Reflective method invocation — used to hide API calls from static analysis.",
        tags=["evasion"],
    ),
    CodePattern(
        "getDeclaredMethod", ThreatCategory.REFLECTION, "HIGH", 45,
        "Access private methods via reflection — common evasion technique.",
        tags=["evasion"],
    ),
    CodePattern(
        "forName", ThreatCategory.REFLECTION, "MEDIUM", 25,
        "Class.forName() — dynamic class resolution, often paired with invoke().",
    ),
    CodePattern(
        "setAccessible", ThreatCategory.REFLECTION, "HIGH", 40,
        "Bypasses Java access modifiers — used to invoke hidden system APIs.",
        tags=["evasion"],
    ),

    # Native Code / Shell Execution
    CodePattern(
        "Runtime.getRuntime().exec", ThreatCategory.NATIVE_CODE, "CRITICAL", 85,
        "Execute shell commands — root exploits, command execution payloads.",
        tags=["rce", "root"],
    ),
    CodePattern(
        "ProcessBuilder", ThreatCategory.NATIVE_CODE, "HIGH", 60,
        "Process creation — alternative shell execution API.",
        tags=["rce"],
    ),
    CodePattern(
        "System.loadLibrary", ThreatCategory.NATIVE_CODE, "MEDIUM", 30,
        "Load native .so library — native code execution (JNI).",
    ),
    CodePattern(
        "System.load(", ThreatCategory.NATIVE_CODE, "HIGH", 55,
        "Load arbitrary native library from path — rootkit dropper signature.",
        tags=["rootkit"],
    ),
    CodePattern(
        "/system/bin/sh", ThreatCategory.NATIVE_CODE, "CRITICAL", 90,
        "Shell reference in strings — direct root shell execution.",
        tags=["root", "rce"],
    ),
    CodePattern(
        "su\x00", ThreatCategory.PRIVILEGE_ESC, "CRITICAL", 95,
        "Root 'su' binary call — privilege escalation.",
        tags=["root"],
    ),
    CodePattern(
        "chmod 777", ThreatCategory.PRIVILEGE_ESC, "CRITICAL", 90,
        "World-writable permission setting — privilege abuse.",
        tags=["root"],
    ),

    # Cryptography (suspicious use)
    CodePattern(
        "javax.crypto.Cipher", ThreatCategory.CRYPTO, "MEDIUM", 20,
        "Cryptographic cipher — legitimate in banking apps; suspicious in unknown apps.",
    ),
    CodePattern(
        "AES/CBC", ThreatCategory.CRYPTO, "MEDIUM", 15,
        "AES encryption mode — ransomware uses this to encrypt victim files.",
        tags=["ransomware"],
    ),
    CodePattern(
        "RSA/ECB", ThreatCategory.CRYPTO, "MEDIUM", 20,
        "RSA encryption — C2 communication encryption.",
    ),
    CodePattern(
        "SecretKeySpec", ThreatCategory.CRYPTO, "LOW", 10,
        "Symmetric key construction — check hardcoded key values.",
    ),

    # Network / C2
    CodePattern(
        "HttpURLConnection", ThreatCategory.NETWORK, "LOW", 5,
        "HTTP connection — baseline network. Suspicious combined with dynamic code loading.",
    ),
    CodePattern(
        "OkHttpClient", ThreatCategory.NETWORK, "LOW", 5,
        "OkHttp networking — common library.",
    ),
    CodePattern(
        "Socket(", ThreatCategory.NETWORK, "MEDIUM", 25,
        "Raw TCP socket — C2 communication, port scanning.",
        tags=["c2"],
    ),
    CodePattern(
        "DatagramSocket", ThreatCategory.NETWORK, "MEDIUM", 20,
        "UDP socket — DNS tunneling or UDP-based C2.",
        tags=["c2"],
    ),
    CodePattern(
        "ServerSocket", ThreatCategory.NETWORK, "HIGH", 50,
        "Listens for incoming connections — backdoor server.",
        tags=["backdoor"],
    ),
    CodePattern(
        "tor2web", ThreatCategory.NETWORK, "CRITICAL", 95,
        "Tor2Web reference — C2 anonymization via Tor.",
        tags=["c2", "tor"],
    ),
    CodePattern(
        ".onion", ThreatCategory.NETWORK, "CRITICAL", 95,
        "Tor hidden service address — ransomware C2 infrastructure.",
        tags=["c2", "tor", "ransomware"],
    ),

    # Surveillance
    CodePattern(
        "android.telephony.SmsManager", ThreatCategory.SMS_FRAUD, "HIGH", 60,
        "SMS manager — direct SMS sending API.",
        tags=["sms_fraud"],
    ),
    CodePattern(
        "sendTextMessage", ThreatCategory.SMS_FRAUD, "HIGH", 70,
        "Send SMS programmatically — premium-rate SMS fraud.",
        tags=["sms_fraud"],
    ),
    CodePattern(
        "android.location.LocationManager", ThreatCategory.SURVEILLANCE, "MEDIUM", 25,
        "GPS location tracking.",
    ),
    CodePattern(
        "android.media.MediaRecorder", ThreatCategory.SURVEILLANCE, "HIGH", 55,
        "Audio/video recording — surveillance.",
        tags=["stalkerware"],
    ),
    CodePattern(
        "getCameraId", ThreatCategory.SURVEILLANCE, "HIGH", 50,
        "Camera enumeration — background photo/video capture.",
        tags=["stalkerware"],
    ),
    CodePattern(
        "android.provider.CallLog", ThreatCategory.SURVEILLANCE, "HIGH", 55,
        "Call log access — surveillance data exfiltration.",
        tags=["stalkerware"],
    ),

    # Persistence
    CodePattern(
        "BOOT_COMPLETED", ThreatCategory.PERSISTENCE, "MEDIUM", 25,
        "Boot broadcast receiver — auto-start on device reboot.",
    ),
    CodePattern(
        "JobScheduler", ThreatCategory.PERSISTENCE, "LOW", 10,
        "Scheduled job — persistence via periodic execution.",
    ),
    CodePattern(
        "AlarmManager", ThreatCategory.PERSISTENCE, "LOW", 10,
        "Alarm-based periodic wake — persistence mechanism.",
    ),
    CodePattern(
        "WorkManager", ThreatCategory.PERSISTENCE, "LOW", 10,
        "Background work scheduling — persistence.",
    ),

    # Anti-Analysis / Obfuscation
    CodePattern(
        "isDebuggerConnected", ThreatCategory.ANTI_ANALYSIS, "HIGH", 60,
        "Debugger detection — malware halts execution under analysis tools.",
        tags=["evasion", "anti_debug"],
    ),
    CodePattern(
        "android.os.Debug.isDebuggerConnected", ThreatCategory.ANTI_ANALYSIS, "HIGH", 65,
        "Checks for attached debugger — anti-analysis evasion.",
        tags=["evasion", "anti_debug"],
    ),
    CodePattern(
        "getprop ro.build.tags", ThreatCategory.ANTI_ANALYSIS, "HIGH", 60,
        "Checks if device is an emulator via build tags.",
        tags=["anti_emulator"],
    ),
    CodePattern(
        "Bluestacks", ThreatCategory.ANTI_ANALYSIS, "HIGH", 55,
        "Emulator name string — emulator detection evasion.",
        tags=["anti_emulator"],
    ),
    CodePattern(
        "Genymotion", ThreatCategory.ANTI_ANALYSIS, "HIGH", 55,
        "Emulator name string — emulator detection evasion.",
        tags=["anti_emulator"],
    ),
    CodePattern(
        "com.android.vending.CHECK_LICENSE", ThreatCategory.ANTI_ANALYSIS, "MEDIUM", 20,
        "License check (LVL) — sometimes used to restrict execution context.",
    ),
    CodePattern(
        "PackageManager.GET_SIGNATURES", ThreatCategory.ANTI_ANALYSIS, "MEDIUM", 25,
        "Signature verification check — tamper detection or anti-repack.",
    ),

    # Accessibility Abuse
    CodePattern(
        "AccessibilityService", ThreatCategory.ACCESSIBILITY_ABU, "CRITICAL", 90,
        "Accessibility service — banking trojans use this for screen scraping and overlay attacks.",
        tags=["banking_trojan", "overlay"],
    ),
    CodePattern(
        "performAction", ThreatCategory.ACCESSIBILITY_ABU, "HIGH", 55,
        "Automated UI interaction via Accessibility — auto-click and form fill attacks.",
        tags=["banking_trojan"],
    ),
    CodePattern(
        "TYPE_WINDOW_STATE_CHANGED", ThreatCategory.ACCESSIBILITY_ABU, "HIGH", 50,
        "Monitors window transitions — detects when banking apps are opened.",
        tags=["banking_trojan"],
    ),

    # Ransomware indicators
    CodePattern(
        "getExternalFilesDir", ThreatCategory.RANSOMWARE, "MEDIUM", 15,
        "External storage enumeration — file discovery before encryption.",
    ),
    CodePattern(
        "lockNow", ThreatCategory.RANSOMWARE, "CRITICAL", 85,
        "DevicePolicyManager.lockNow() — locks screen immediately, ransomware payload.",
        tags=["ransomware"],
    ),
    CodePattern(
        "resetPassword", ThreatCategory.RANSOMWARE, "CRITICAL", 90,
        "DevicePolicyManager.resetPassword() — changes device PIN, ransomware lockout.",
        tags=["ransomware"],
    ),
    CodePattern(
        "setStorageEncryption", ThreatCategory.RANSOMWARE, "CRITICAL", 95,
        "Device storage encryption via DevicePolicyManager — ransomware.",
        tags=["ransomware"],
    ),
]


# ── Suspicious string patterns (regex) ───────────────────────────
STRING_PATTERNS: list[tuple[str, str, str, int]] = [
    # (regex, category, description, score)
    (r"https?://(?:\d{1,3}\.){3}\d{1,3}[:/]", "C2 Infrastructure", "HTTP connection to raw IP address — C2 server pattern.", 60),
    (r"(?:\d{1,3}\.){3}\d{1,3}:\d{4,5}", "C2 Infrastructure", "IP:port combination — direct C2 socket address.", 65),
    (r"\.onion", "Tor C2", "Tor hidden service — anonymized C2 infrastructure.", 90),
    (r"(?:http|ftp)s?://[^\s\"']{3,}\.(?:tk|pw|cc|xyz|top|gq|ml|ga|cf)\b", "Suspicious TLD", "High-risk TLD domain — commonly used for malware hosting.", 50),
    (r"base64_decode|atob\(|fromBase64|Base64\.decode", "Encoded Payload", "Base64 decoding at runtime — obfuscated payload delivery.", 45),
    (r"eval\s*\(|exec\s*\(", "Code Execution", "Dynamic code evaluation — obfuscated execution.", 70),
    (r"(?:password|passwd|secret|api_key|apikey|token)\s*=\s*[\"'][^\"']{4,}", "Hardcoded Secret", "Hardcoded credential or API key in source.", 75),
    (r"/proc/net/tcp", "Network Scanning", "Reads kernel TCP connection table — port scanner / spy.", 60),
    (r"(?:wget|curl)\s+http", "Downloader", "Shell download command — dropper payload delivery.", 80),
    (r"pm\s+install\s+-r", "Silent Install", "Shell command to install APK silently — dropper.", 85),
    (r"am\s+startservice", "Service Manipulation", "Shell command to start services — privilege abuse.", 55),
    (r"content://sms", "SMS Access", "SMS content provider URI — reading SMS messages.", 65),
    (r"content://contacts", "Contact Access", "Contacts content provider URI — contact harvesting.", 40),
    (r"/data/data/com\.android\.providers", "Data Provider", "Direct access to Android internal data providers.", 50),
    (r"(?:Lcom/google/android/gms/ads|doubleclick\.net|admob)", "Adware", "Ad network reference — context-dependent.", 10),
    (r"(?:supesu|chainfire|superuser)", "Root Binary", "Root management app reference — indicates root access.", 70),
]
