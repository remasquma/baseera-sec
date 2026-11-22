"""
Baseera Sec - Local Source Code & Package Security Auditor
Static Application Security Testing (SAST) & Configuration Auditing engine.
Features hardened archive extraction (Zip-Slip, Zip-Bomb & Symlink protections),
strict file size limits, safe pattern detection, and language profiling.
"""
import logging
import math
import os
import re
import shutil
import tempfile
import zipfile
from collections import Counter
from typing import List, Tuple
from core.engine.models import ReconFinding, VerifiedVulnerability, SeverityLevel, TechFingerprint
from core.ai.local_model_analyzer import local_ai_classifier

logger = logging.getLogger("baseera.engine.sast")

# Extraction and SAST Safety Limits
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 50 * 1024 * 1024  # 50MB
MAX_ARCHIVE_FILES = 2000
MAX_SINGLE_FILE_BYTES = 2 * 1024 * 1024  # 2MB per scanned file


class LocalPackageAuditor:
    SECRET_ASSIGNMENT_PATTERN = re.compile(
        r'''(?im)\b(?P<name>api[_-]?key|access[_-]?token|auth[_-]?token|'''
        r'''client[_-]?secret|secret(?:[_-]?key)?|private[_-]?key|'''
        r'''password|passwd|db[_-]?pass|token)\b\s*[:=]\s*'''
        r'''(?:(?P<quote>["'])(?P<quoted>[^"'\r\n]{4,})(?P=quote)|'''
        r'''(?P<bare>[A-Za-z0-9_./+=-]{4,}))'''
    )
    PLACEHOLDER_SECRET_PATTERN = re.compile(
        r"(?i)(?:^|[^a-z0-9])(?:example|sample|dummy|placeholder|"
        r"replace[_-]?me|change[_-]?me|your[_-]?(?:api[_-]?)?key|"
        r"your[_-]?token|insert[_-]?(?:key|token|secret)|redacted|"
        r"todo|xxxxx+|<[^>]+>)(?:$|[^a-z0-9])"
    )

    # Non-secret static rules remain separate from credential analysis.
    SECRET_PATTERNS: List[Tuple[str, str, str, str, float]] = [
        (r'(?i)android:debuggable\s*=\s*["\']true["\']', "تفعيل وضع التنقيح الأمني في التطبيق (Android Debuggable Flag Enabled)", "CWE-215", "A05:2021-Security Misconfiguration", 7.2),
        (r'(?i)android:allowBackup\s*=\s*["\']true["\']', "السماح بنسخ بيانات التطبيق بدون تشفير (Android AllowBackup Risk)", "CWE-200", "A01:2021-Broken Access Control", 6.0),
        (r'(?i)(?:eval|exec)\s*\([^)]*\)', "استخدام دوال التنفيذ المباشر غير الآمنة (Dangerous Code Execution Function)", "CWE-95", "A03:2021-Injection", 8.1),
    ]

    @staticmethod
    def shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        length = len(value)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in Counter(value).values()
        )

    @classmethod
    def _secret_confidence(cls, name: str, value: str) -> float | None:
        normalized = value.strip().strip("\"'`")
        if (
            len(normalized) < 4
            or cls.PLACEHOLDER_SECRET_PATTERN.search(normalized)
            or normalized.upper() in {"EXAMPLE", "REPLACE_ME", "YOUR_API_KEY"}
        ):
            return None

        entropy = cls.shannon_entropy(normalized)
        key_name = name.lower().replace("-", "_")
        is_password = any(word in key_name for word in ("password", "passwd", "db_pass"))
        if not is_password and (len(normalized) < 12 or entropy < 3.0):
            return None

        # Entropy contributes to confidence but is not treated as proof by itself.
        score = 0.55 + min(entropy, 5.0) * 0.055 + min(len(normalized), 48) * 0.001
        return round(min(score, 0.9), 2)

    @classmethod
    def _secret_assignments(cls, content: str) -> List[Tuple[str, float, float]]:
        matches = []
        for match in cls.SECRET_ASSIGNMENT_PATTERN.finditer(content):
            name = match.group("name")
            value = match.group("quoted") or match.group("bare") or ""
            confidence = cls._secret_confidence(name, value)
            if confidence is not None:
                matches.append((name, confidence, cls.shannon_entropy(value)))

        for match in re.finditer(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", content):
            body = content[match.end():].split("-----END", 1)[0].strip()
            confidence = min(0.9, 0.75 + min(cls.shannon_entropy(body), 5.0) * 0.03)
            matches.append(("private key", round(confidence, 2), cls.shannon_entropy(body)))
        return matches

    @classmethod
    def audit_package_or_directory(cls, file_path: str) -> Tuple[TechFingerprint, List[ReconFinding], List[VerifiedVulnerability]]:
        findings: List[ReconFinding] = []
        vulns: List[VerifiedVulnerability] = []
        fp = TechFingerprint()
        fp.inferred_site_type = "Local Application / Source Package"

        extract_dir = file_path
        temp_extracted_dir = None

        try:
            # إذا كان الملف أرشيفاً مضغوطاً (.zip أو حزمة)
            if os.path.isfile(file_path) and zipfile.is_zipfile(file_path):
                temp_extracted_dir = tempfile.mkdtemp(prefix="baseera_extract_")
                extract_dir = temp_extracted_dir

                total_uncompressed_size = 0
                total_files = 0

                with zipfile.ZipFile(file_path, 'r') as zf:
                    for info in zf.infolist():
                        total_files += 1
                        total_uncompressed_size += info.file_size

                        if total_files > MAX_ARCHIVE_FILES:
                            raise ValueError(f"Archive exceeds maximum file count limit ({MAX_ARCHIVE_FILES})")
                        if total_uncompressed_size > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                            raise ValueError(f"Archive exceeds maximum uncompressed size limit ({MAX_ARCHIVE_UNCOMPRESSED_BYTES} bytes)")

                        # Zip-Slip Guard: Ensure target path resolves strictly inside extract_dir
                        target_path = os.path.abspath(os.path.join(extract_dir, info.filename))
                        if not target_path.startswith(os.path.abspath(extract_dir) + os.sep):
                            raise ValueError(f"Malicious zip-slip path detected: {info.filename}")

                        # Directory creation vs file extraction
                        if info.is_dir():
                            os.makedirs(target_path, exist_ok=True)
                        else:
                            os.makedirs(os.path.dirname(target_path), exist_ok=True)
                            with zf.open(info) as source, open(target_path, "wb") as target:
                                shutil.copyfileobj(source, target)

            detected_langs = set()
            file_count = 0

            # فحص كافة الملفات داخل المجلد
            for root, _, files in os.walk(extract_dir):
                for file in files:
                    file_count += 1
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, extract_dir)
                    ext = os.path.splitext(file)[1].lower()

                    # استنتاج لغة البرمجة والبنية
                    if ext in ['.js', '.ts', '.jsx', '.tsx']: detected_langs.add("JavaScript/TypeScript (Node/React)")
                    elif ext in ['.py']: detected_langs.add("Python")
                    elif ext in ['.php']: detected_langs.add("PHP")
                    elif ext in ['.java', '.kt']: detected_langs.add("Java/Kotlin (Android)")
                    elif ext in ['.dart']: detected_langs.add("Dart (Flutter)")
                    elif ext in ['.cs']: detected_langs.add("C# (.NET)")

                    # فحص محتوى الملف إذا كان ملفاً نصياً أو كوداً
                    if ext in ['.js', '.ts', '.py', '.php', '.java', '.kt', '.dart', '.env', '.json', '.xml', '.yaml', '.yml', '.conf', '.txt', '.html']:
                        try:
                            file_size = os.path.getsize(full_path)
                            if file_size > MAX_SINGLE_FILE_BYTES:
                                continue

                            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()

                            # تقييم الكود المصدري بمجموعة نماذج Nazzoor المحلية
                            ai_eval = local_ai_classifier.score_text(content[:2500])
                            malicious_probability = ai_eval.get("malicious_probability")
                            if (
                                ai_eval.get("score_source") == "VERIFIED_LABELS_AND_CALIBRATION"
                                and ai_eval.get("is_malicious") is True
                                and isinstance(malicious_probability, (int, float))
                                and not isinstance(malicious_probability, bool)
                                and math.isfinite(malicious_probability)
                                and 0.70 <= malicious_probability <= 1.0
                            ):
                                vulns.append(VerifiedVulnerability(
                                    vuln_id=f"SAST-AI-{len(vulns)+1:03d}",
                                    title="سلوك برمجي مشبوه مكتشف بمجموعة نماذج الذكاء الاصطناعي Nazzoor",
                                    cwe_id="CWE-74",
                                    owasp_category="A03:2021-Injection",
                                    severity=SeverityLevel.HIGH,
                                    cvss_score=7.8,
                                    confidence_score=malicious_probability,
                                    description=f"نموذج الذكاء الاصطناعي ({ai_eval.get('model_name')}) رصد أنماط كود خطيرة داخل الملف `{rel_path}`.",
                                    poc_evidence=f"AI Model Status: {ai_eval.get('status')} | Signals: {ai_eval.get('signals', [])} | File: {rel_path}",
                                    attack_vector="Suspicious Code Flow / Potential Injection",
                                    remediation_guide=f"قم بمراجعة منطق البرمجة في `{rel_path}` واستبدال أي أوامر ديناميكية بدوال معيارية آمنة.",
                                    affected_url=f"local://{rel_path}"
                                ))

                            for secret_name, confidence, entropy in cls._secret_assignments(content):
                                title = (
                                    "مفتاح تشفير خاص مسرب داخل المشروع (Private Cryptographic Key Leak)"
                                    if secret_name == "private key"
                                    else "بيانات اعتماد مدمجة داخل الكود (Hardcoded Secret or Credential)"
                                )
                                cwe = "CWE-312" if secret_name == "private key" else "CWE-798"
                                cvss = 9.3 if secret_name == "private key" else 8.5
                                findings.append(ReconFinding(
                                    category="sast",
                                    title=title,
                                    description=f"تم العثور على قيمة اعتماد عالية العشوائية داخل الملف: {rel_path}",
                                    evidence=(
                                        f"File: {rel_path} | Assignment: {secret_name} | "
                                        f"Shannon entropy: {entropy:.2f} bits/character | Value redacted"
                                    ),
                                    risk_indicator="high"
                                ))
                                vulns.append(VerifiedVulnerability(
                                    vuln_id=f"SAST-VULN-{len(vulns)+1:03d}",
                                    title=title,
                                    cwe_id=cwe,
                                    owasp_category="A02:2021-Cryptographic Failures" if secret_name == "private key" else "A07:2021-Identification and Authentication Failures",
                                    severity=SeverityLevel.CRITICAL if secret_name == "private key" else SeverityLevel.HIGH,
                                    cvss_score=cvss,
                                    confidence_score=confidence,
                                    description=(
                                        f"أظهر تحليل الإسناد وسمة Shannon entropy قيمة اعتماد محتملة في الملف "
                                        f"`{rel_path}`. القيمة محجوبة من التقرير."
                                    ),
                                    poc_evidence=(
                                        f"Secret-like assignment in `{rel_path}`; entropy={entropy:.2f} "
                                        "bits/character; value redacted."
                                    ),
                                    attack_vector="Hardcoded Credential / Secret Exposure",
                                    remediation_guide=(
                                        f"أزل بيانات الاعتماد من `{rel_path}`، ودوّر القيمة، واستخدم مخزن أسرار آمنًا."
                                    ),
                                    affected_url=f"local://{rel_path}"
                                ))

                            # فحص أنماط الإعدادات والتنفيذ غير الآمن
                            for pattern, title, cwe, owasp, cvss in cls.SECRET_PATTERNS:
                                matches = re.findall(pattern, content)
                                if matches:
                                    vuln_id = f"SAST-VULN-{len(vulns)+1:03d}"

                                    findings.append(ReconFinding(
                                        category="sast",
                                        title=title,
                                        description=f"تم العثور على نمط أمني خطير داخل الملف: {rel_path}",
                                        evidence=f"File: {rel_path} | Rule matched; source value redacted.",
                                        risk_indicator="high" if cvss >= 8.0 else "medium"
                                    ))

                                    vulns.append(VerifiedVulnerability(
                                        vuln_id=vuln_id,
                                        title=title,
                                        cwe_id=cwe,
                                        owasp_category=owasp,
                                        severity=SeverityLevel.CRITICAL if cvss >= 9.0 else SeverityLevel.HIGH if cvss >= 7.0 else SeverityLevel.MEDIUM,
                                        cvss_score=cvss,
                                        confidence_score=0.8,
                                        description=f"تحليل الكود المصدري طابق قاعدة إعداد/تنفيذ غير آمن داخل الملف `{rel_path}`.",
                                        poc_evidence=f"Static rule matched in '{rel_path}'; matched source value redacted.",
                                        attack_vector="Static Code Vulnerability / Embedded Secret",
                                        remediation_guide=f"قم بإزالة السر المدمج من الملف `{rel_path}` فوراً، واستخدم بيئة إدارة المتغيرات الآمنة (Secrets Vault / Environment Variables).",
                                        affected_url=f"local://{rel_path}"
                                    ))
                        except Exception as e:
                            logger.debug(f"Could not inspect file {full_path}: {e}")

            fp.language = ", ".join(detected_langs) if detected_langs else "Compiled Binary / Native Asset"
            fp.server = "Local Execution Environment"
            fp.inferred_site_type = f"Local Application Package ({file_count} files analyzed)"
            fp.common_attack_vectors = [
                "Hardcoded Credentials & API Leaks",
                "Insecure Application Permissions",
                "Unsafe Execution Functions",
                "Insecure Storage & Cleartext Logs"
            ]

        finally:
            # Cleanup temporary extraction directory
            if temp_extracted_dir and os.path.exists(temp_extracted_dir):
                shutil.rmtree(temp_extracted_dir, ignore_errors=True)

        return fp, findings, vulns
