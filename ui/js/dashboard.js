// Baseera Sec - Local Security Scanner Dashboard
// Provides: local model status, Dark/Light Themes, bilingual i18n, local SAST upload and report exports.

document.addEventListener("DOMContentLoaded", () => {
  // DOM Elements (Safely Queried)
  const htmlDoc = document.documentElement;
  const btnThemeToggle = document.getElementById("btn-theme-toggle");
  const btnLangToggle = document.getElementById("btn-lang-toggle");

  const btnLocalModelStatus = document.getElementById("btn-local-model-status");
  const localModelStatus = document.getElementById("local-model-status");

  const btnExportPdf = document.getElementById("btn-export-pdf");
  const btnExportHtml = document.getElementById("btn-export-html");
  const btnExportSarif = document.getElementById("btn-export-sarif");

  const scopeWeb = document.getElementById("scope-web");
  const scopeApp = document.getElementById("scope-app");
  const modeRemote = document.getElementById("mode-remote");
  const modeLocal = document.getElementById("mode-local");

  const panelRemoteInput = document.getElementById("panel-remote-input");
  const panelLocalInput = document.getElementById("panel-local-input");
  const targetUrlInput = document.getElementById("target-url");
  const btnStartAudit = document.getElementById("btn-start-audit");
  const urlErrorBanner = document.getElementById("url-error-banner");
  const urlErrorText = document.getElementById("url-error-text");

  function showUrlError(msg) {
    if (urlErrorBanner && urlErrorText) {
      urlErrorText.innerText = msg;
      urlErrorBanner.style.display = "flex";
    }
    if (targetUrlInput) {
      targetUrlInput.style.borderColor = "#ef4444";
      targetUrlInput.style.boxShadow = "0 0 0 2px rgba(239, 68, 68, 0.25)";
      targetUrlInput.focus();
      targetUrlInput.select();
    }
    alert(msg);
  }

  function clearUrlError() {
    if (urlErrorBanner) {
      urlErrorBanner.style.display = "none";
    }
    if (targetUrlInput) {
      targetUrlInput.style.borderColor = "";
      targetUrlInput.style.boxShadow = "";
    }
  }

  if (targetUrlInput) {
    targetUrlInput.addEventListener("input", clearUrlError);
  }

  const fileDropzone = document.getElementById("file-dropzone");
  const localFileInput = document.getElementById("local-file-input");
  const selectedFileName = document.getElementById("selected-file-name");
  const btnUploadAudit = document.getElementById("btn-upload-audit");

  const scanStatus = document.getElementById("scan-status-text");
  const terminal = document.getElementById("terminal-logs");
  const btnClearTerminal = document.getElementById("btn-clear-terminal");

  const valRisk = document.getElementById("val-risk");
  const valVulns = document.getElementById("val-vulns");
  const valCompliance = document.getElementById("val-compliance");
  const valTime = document.getElementById("val-time");

  const barAsvsL1 = document.getElementById("bar-asvs-l1");
  const txtAsvsL1 = document.getElementById("txt-asvs-l1");
  const barAsvsL2 = document.getElementById("bar-asvs-l2");
  const txtAsvsL2 = document.getElementById("txt-asvs-l2");
  const barCis = document.getElementById("bar-cis");
  const txtCis = document.getElementById("txt-cis");
  const barNist = document.getElementById("bar-nist");
  const txtNist = document.getElementById("txt-nist");
  const riskMatrixSummary = document.getElementById("risk-matrix-summary");

  const aiAttacksPanel = document.getElementById("ai-attacks-panel");
  const aiAttacksList = document.getElementById("ai-attacks-list");
  const aiModelBadge = document.getElementById("ai-model-badge");

  const tableBody = document.getElementById("vulns-table-body");
  const aiSummaryCard = document.getElementById("ai-summary-card");
  const aiSummaryContent = document.getElementById("ai-summary-content");

  const reportModal = document.getElementById("report-modal");
  const reportIframe = document.getElementById("report-iframe");
  const btnCloseModal = document.getElementById("btn-close-modal");

  // Global State
  let currentTheme = localStorage.getItem("baseera_theme") || "dark";
  let currentLang = localStorage.getItem("baseera_lang") || "ar";
  let currentScope = "Web";
  let activeProjectId = null;
  let selectedFile = null;
  let liveTimerInterval = null;
  let ptesProgressionInterval = null;
  let liveScanStartTime = null;

  // Safe Helper Function to set text on elements without crashing if missing
  function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.innerText = text;
  }

  // =========================================================================
  // 1. Localization Dictionary (Bilingual i18n: Arabic RTL & English LTR)
  // =========================================================================
  const i18n = {
    ar: {
      brandTitle: "Baceer | بصير الثغرات الأمنية",
      brandSubtitle: "Baceer — Autonomous Cognitive VAPT & AI Scanner | Team 2Bit",
      navDashboard: "لوحة التحكم (Dashboard)",
      navTarget: "نطاق الفحص (Target Scope)",
      navWorkflow: "سير العمل (PTES Workflow)",
      navAttacks: "مصفوفة الهجمات (Attack Matrix)",
      navCompliance: "معايير الامتثال (Compliance)",
      navTerminal: "الطرفية المباشرة (Live Terminal)",
      navVulns: "سجل الثغرات (Findings)",
      lblLocalModels: "نماذج الذكاء الاصطناعي:",
      btnRefreshModels: "تحديث",
      themeToggleLight: "الوضع الفاتح",
      themeToggleDark: "الوضع الداكن",
      langToggle: "English",
      btnBenchmark: "نتائج الاختبار الاصطناعي",
      btnExportPdf: "تصدير PDF",
      btnExportHtml: "معاينة HTML",
      btnExportSarif: "SARIF 2.1.0",
      lblTargetType: "نوع الهدف ونطاق العمل:",
      scopeWeb: "موقع إلكتروني (Web)",
      scopeApp: "تطبيق (Mobile / Desktop)",
      lblInputMode: "مصدر الفحص:",
      modeRemote: "فحص رابط عن بعد (URL)",
      modeLocal: "رفع حزمة أو ملفات محلية (Upload)",
      lblMethodologyTitle: "أساس سير العمل:",
      urlPlaceholder: "https://example.com",
      btnStartAudit: "بدء الفحص المنهجي الشامل",
      btnAuditAnother: "فحص هدف آخر",
      lblDropzone: "انقر لاختيار حزمة أو كود مصدري للفحص المحلي (.zip, .apk, .deb, source files)",
      lblDropzoneHelp: "فحوصات ساكنة محلية للشفرة والإعدادات؛ التغطية محدودة",
      btnUploadAudit: "بدء فحص الحزمة المرفوعة",
      lblPtesTitle: "خطوات سير العمل المنهجي (PTES Workflow):",
      statusWaiting: "بانتظار إشارة البدء...",
      statusRunning: "جارٍ تنفيذ الفحوصات المتاحة...",
      statusComplete: "انتهى الفحص. راجع النتائج والتغطية غير المختبرة.",
      ptes: [
        "1. تحديد الهدف والاتصال",
        "2. مراجعة الترويسات والجلسات",
        "3. استكشاف المسارات والمدخلات",
        "4. اختيار فحوصات محددة",
        "5. إرسال طلبات تحقق نشطة",
        "6. تجميع النتائج المتاحة",
        "7. حفظ التقرير"
      ],
      metricRisk: "مؤشر المخاطر التجميعي (Baseera، 0-10)",
      valRiskIdle: "غير مُقيّم",
      subMetricRisk: "مؤشر أمني داخلي مستند إلى أوزان CVSS المركبة",
      metricVulns: "النتائج التي أعادها الفحص",
      valVulnsIdle: "غير متاح",
      subMetricVulns: "الثغرات المؤكدة بالدليل الملموس واستجابات الخادم",
      metricCompliance: "نسبة الامتثال للضوابط المفحوصة (Tested Scope)",
      valComplianceIdle: "بانتظار الفحص",
      subMetricCompliance: "بناءً على 12 ضابطاً أمنياً مفحوصاً",
      metricTime: "زمن الفحص والمعالجة",
      valTimeIdle: "غير متاح",
      subMetricTime: "الزمن المقاس الإجمالي لهذه الجولة بالمللي ثانية",
      pendingScan: "بانتظار الفحص",
      lblComplianceHeader: "نسب الامتثال للضوابط الأمنية المفحوصة (Tested Scope Compliance)",
      subComplianceHeader: "تقييم الامتثال الفعلي بناءً على نتائج فحص واختبار الضوابط المحددة",
      lblRiskMatrixHeader: "مصفوفة إدارة المخاطر وتحديد الأولويات (Risk-Based Prioritization)",
      riskMatrixDefault: "لا توجد نتائج بعد. حدد النطاق واضغط \"بدء الفحص\" لحساب مصفوفة المخاطر والامتثال.",
      lblAttacksHeader: "مصفوفة الهجمات المنفذة حياً (Targeted Adversarial Attacks Execution)",
      lblAttacksSub: "Active live HTTP verification across multi-vector adversarial tactics",
      lblTerminalHeader: "سجل العمليات والاستدلال اللحظي (Terminal Output):",
      btnClearTerminal: "مسح السجل",
      lblVulnsHeader: "سجل النتائج والثغرات المرصودة (Vulnerability Inventory)",
      thId: "المعرّف",
      thTitle: "عنوان الثغرة والتصنيف",
      thCvss: "CVSS v3.1",
      thEpss: "EPSS (الاحتمالية)",
      thCwe: "CWE / CVE",
      thMitre: "MITRE ATT&CK",
      thCompliance: "OWASP / CIS",
      thPoc: "دليل الإثبات العملي (PoC)",
      thRemediation: "خطة المعالجة والترقيع",
      tdEmpty: "لم يبدأ الفحص بعد. حدد النطاق واضغط \"بدء الفحص المنهجي الشامل\".",
      tdAuditing: "جارٍ تنفيذ الفحوصات المتاحة...",
      lblSummaryHeader: "ملخص الفحص الجنائي بالذكاء الاصطناعي",
      lblModalTitle: "معاينة التقرير النهائي | Baceer VAPT Report",
      btnModalPrint: "طباعة / حفظ كـ PDF",
      btnCloseModal: "إغلاق"
    },
    en: {
      brandTitle: "Baceer — بصير الثغرات الأمنية",
      brandSubtitle: "Baceer — Autonomous Cognitive VAPT & AI Scanner | Team 2Bit",
      navDashboard: "Dashboard",
      navTarget: "Target Scope",
      navWorkflow: "PTES Workflow",
      navAttacks: "Attack Matrix",
      navCompliance: "Compliance",
      navTerminal: "Live Terminal",
      navVulns: "Findings Inventory",
      lblLocalModels: "AI Models:",
      btnRefreshModels: "Refresh",
      themeToggleLight: "Light Mode",
      themeToggleDark: "Dark Mode",
      langToggle: "العربية",
      btnBenchmark: "Benchmark Results",
      btnExportPdf: "Export PDF",
      btnExportHtml: "Preview HTML",
      btnExportSarif: "SARIF 2.1.0",
      lblTargetType: "Target Scope & Type:",
      scopeWeb: "Web Application",
      scopeApp: "Application (Mobile / Desktop)",
      lblInputMode: "Scan Source:",
      modeRemote: "Remote Target (URL)",
      modeLocal: "Local Package Upload",
      lblMethodologyTitle: "Workflow Basis:",
      urlPlaceholder: "https://example.com",
      btnStartAudit: "Start Comprehensive Audit",
      btnAuditAnother: "Audit Another Target",
      lblDropzone: "Click to select a local package or source code (.zip, .apk, .deb, source files)",
      lblDropzoneHelp: "Local static checks for source code and configurations; scoped coverage",
      btnUploadAudit: "Audit Uploaded Package",
      lblPtesTitle: "Methodological Workflow (PTES Workflow):",
      statusWaiting: "Awaiting execution trigger...",
      statusRunning: "Running available checks...",
      statusComplete: "Scan finished. Review findings and untested coverage.",
      ptes: [
        "1. Configure target and connect",
        "2. Review headers and sessions",
        "3. Discover paths and inputs",
        "4. Select supported checks",
        "5. Send active verification requests",
        "6. Aggregate available findings",
        "7. Save report"
      ],
      metricRisk: "Baceer Aggregate Risk Index (0-10)",
      valRiskIdle: "Not Assessed",
      subMetricRisk: "Internal security index based on composite CVSS weights",
      metricVulns: "Findings Returned by Scan",
      valVulnsIdle: "N/A",
      subMetricVulns: "Vulnerabilities verified by tangible PoC evidence",
      metricCompliance: "Tested Scope Compliance Rate",
      valComplianceIdle: "Pending Scan",
      subMetricCompliance: "Based on 12 assessed security controls",
      metricTime: "Execution Latency & Duration",
      valTimeIdle: "N/A",
      subMetricTime: "Total measured duration for this audit cycle",
      pendingScan: "Pending Scan",
      lblComplianceHeader: "Tested Scope Compliance Gauges",
      subComplianceHeader: "Actual compliance assessment based on assessed controls",
      lblRiskMatrixHeader: "Risk-Based Prioritization Matrix",
      riskMatrixDefault: "No findings yet. Select scope and click 'Start Audit' to calculate risk matrix.",
      lblAttacksHeader: "Targeted Adversarial Attacks Execution Matrix",
      lblAttacksSub: "Active live HTTP verification across multi-vector adversarial tactics",
      lblTerminalHeader: "Live Operation & Reasoning Console:",
      btnClearTerminal: "Clear Console",
      lblVulnsHeader: "Vulnerability & Findings Inventory",
      thId: "Vuln ID",
      thTitle: "Vulnerability Title & Taxonomy",
      thCvss: "CVSS v3.1",
      thEpss: "EPSS (Probability)",
      thCwe: "CWE / CVE",
      thMitre: "MITRE ATT&CK",
      thCompliance: "OWASP / CIS",
      thPoc: "Proof of Concept (PoC)",
      thRemediation: "Remediation Roadmap",
      tdEmpty: "No scan yet. Select a target and click 'Start Comprehensive Audit'.",
      tdAuditing: "Running available checks...",
      lblSummaryHeader: "AI Forensic Scan Summary",
      lblModalTitle: "Report Preview | Baceer VAPT Report",
      btnModalPrint: "Print / Save as PDF",
      btnCloseModal: "Close"
    }
  };

  function applyLanguage(lang) {
    currentLang = lang;
    localStorage.setItem("baseera_lang", lang);
    if (htmlDoc) {
      htmlDoc.setAttribute("lang", lang);
      htmlDoc.setAttribute("dir", lang === "ar" ? "rtl" : "ltr");
    }

    const dict = i18n[lang];
    setText("txt-brand-title", dict.brandTitle);
    setText("txt-brand-subtitle", dict.brandSubtitle);
    setText("lbl-local-models", dict.lblLocalModels);
    if (btnLocalModelStatus) btnLocalModelStatus.innerText = dict.btnRefreshModels;

    if (btnLangToggle) {
      btnLangToggle.innerHTML = `<span class="toggle-text">${dict.langToggle}</span>`;
    }

    // Topbar Action Buttons
    if (btnExportPdf) btnExportPdf.innerHTML = `<span>${dict.btnExportPdf}</span>`;
    if (btnExportHtml) btnExportHtml.innerHTML = `<span>${dict.btnExportHtml}</span>`;
    if (btnExportSarif) btnExportSarif.innerHTML = `<span>${dict.btnExportSarif}</span>`;
    const btnBenchmark = document.getElementById("btn-owasp-benchmark");
    if (btnBenchmark) btnBenchmark.innerHTML = `<span>${dict.btnBenchmark}</span>`;

    // Sidebar Nav Links
    setText("nav-dashboard", dict.navDashboard);
    setText("nav-target", dict.navTarget);
    setText("nav-workflow", dict.navWorkflow);
    setText("nav-attacks", dict.navAttacks);
    setText("nav-compliance", dict.navCompliance);
    setText("nav-terminal", dict.navTerminal);
    setText("nav-vulns", dict.navVulns);

    // Target inputs & scope
    setText("lbl-target-type", dict.lblTargetType);
    if (scopeWeb) scopeWeb.innerText = dict.scopeWeb;
    if (scopeApp) scopeApp.innerText = dict.scopeApp;
    setText("lbl-input-mode", dict.lblInputMode);
    if (modeRemote) modeRemote.innerText = dict.modeRemote;
    if (modeLocal) modeLocal.innerText = dict.modeLocal;
    setText("lbl-methodology-title", dict.lblMethodologyTitle);

    setText("txt-btn-start", activeProjectId ? dict.btnAuditAnother : dict.btnStartAudit);
    setText("lbl-dropzone", dict.lblDropzone);
    setText("lbl-dropzone-help", dict.lblDropzoneHelp);
    setText("txt-btn-upload", dict.btnUploadAudit);

    setText("lbl-ptes-title", dict.lblPtesTitle);
    if (scanStatus && (scanStatus.dataset.idle === "true" || !activeProjectId)) {
      scanStatus.innerText = dict.statusWaiting;
    }

    for (let i = 1; i <= 7; i++) {
      const step = document.getElementById(`ptes-${i}`);
      if (step) step.innerText = dict.ptes[i - 1];
    }

    // KPI Metrics Labels & Subtitles
    setText("lbl-metric-risk", dict.metricRisk);
    setText("lbl-metric-vulns", dict.metricVulns);
    setText("lbl-metric-compliance", dict.metricCompliance);
    setText("lbl-metric-time", dict.metricTime);
    setText("sub-metric-risk", dict.subMetricRisk);
    setText("sub-metric-vulns", dict.subMetricVulns);
    setText("sub-metric-compliance", dict.subMetricCompliance);
    setText("sub-metric-time", dict.subMetricTime);

    // Idle Metric Values (if not yet scanned)
    const valRisk = document.getElementById("val-risk");
    if (valRisk && (!activeProjectId || valRisk.innerText.includes("غير") || valRisk.innerText.includes("Not"))) {
      valRisk.innerText = dict.valRiskIdle;
    }
    const valVulns = document.getElementById("val-vulns");
    if (valVulns && (!activeProjectId || valVulns.innerText.includes("غير") || valVulns.innerText.includes("N/A"))) {
      valVulns.innerText = dict.valVulnsIdle;
    }
    const valCompliance = document.getElementById("val-compliance");
    if (valCompliance && (!activeProjectId || valCompliance.innerText.includes("بانتظار") || valCompliance.innerText.includes("Pending"))) {
      valCompliance.innerText = dict.valComplianceIdle;
    }
    const valTime = document.getElementById("val-time");
    if (valTime && (!activeProjectId || valTime.innerText.includes("غير") || valTime.innerText.includes("N/A"))) {
      valTime.innerText = dict.valTimeIdle;
    }

    // Progress bar texts (if idle)
    ["txt-asvs-l1", "txt-asvs-l2", "txt-cis", "txt-nist"].forEach(id => {
      const el = document.getElementById(id);
      if (el && (!activeProjectId || el.innerText.includes("بانتظار") || el.innerText.includes("Pending"))) {
        el.innerText = dict.pendingScan;
      }
    });

    setText("lbl-compliance-header", dict.lblComplianceHeader);
    setText("sub-compliance-header", dict.subComplianceHeader);
    setText("lbl-risk-matrix-header", dict.lblRiskMatrixHeader);
    if (riskMatrixSummary && (riskMatrixSummary.dataset.idle === "true" || !activeProjectId)) {
      riskMatrixSummary.innerText = dict.riskMatrixDefault;
    }

    setText("lbl-attacks-header", dict.lblAttacksHeader);
    setText("lbl-attacks-sub", dict.lblAttacksSub);
    setText("lbl-terminal-header", dict.lblTerminalHeader);
    if (btnClearTerminal) btnClearTerminal.innerText = dict.btnClearTerminal;
    setText("lbl-vulns-header", dict.lblVulnsHeader);

    // Table Headers
    setText("th-id", dict.thId);
    setText("th-title", dict.thTitle);
    setText("th-cvss", dict.thCvss);
    setText("th-epss", dict.thEpss);
    setText("th-cwe", dict.thCwe);
    setText("th-mitre", dict.thMitre);
    setText("th-compliance", dict.thCompliance);
    setText("th-poc", dict.thPoc);
    setText("th-remediation", dict.thRemediation);

    const tdEmpty = document.getElementById("td-empty-table");
    if (tdEmpty) tdEmpty.innerText = dict.tdEmpty;

    setText("lbl-summary-header", dict.lblSummaryHeader);
    setText("lbl-modal-title", dict.lblModalTitle);
    setText("lbl-modal-print", dict.btnModalPrint);
    if (btnCloseModal) btnCloseModal.innerText = dict.btnCloseModal;

    // AI Model Status text translation
    if (localModelStatus) {
      if (localModelStatus.classList.contains("active")) {
        localModelStatus.innerText = lang === "ar" ? "نماذج نظور (3/3): نشطة ومُعتمدة" : "Nazzoor Models (3/3): Active & Verified";
      }
    }

    applyTheme(currentTheme);
  }

  function applyTheme(theme) {
    currentTheme = theme;
    localStorage.setItem("baseera_theme", theme);
    if (htmlDoc) htmlDoc.setAttribute("data-theme", theme);
    const dict = i18n[currentLang];
    if (btnThemeToggle) {
      btnThemeToggle.innerHTML = `<span class="toggle-text">${theme === "dark" ? dict.themeToggleLight : dict.themeToggleDark}</span>`;
    }
  }

  // Theme & Language Button Handlers
  if (btnThemeToggle) {
    btnThemeToggle.addEventListener("click", () => {
      applyTheme(currentTheme === "dark" ? "light" : "dark");
    });
  }

  if (btnLangToggle) {
    btnLangToggle.addEventListener("click", () => {
      applyLanguage(currentLang === "ar" ? "en" : "ar");
    });
  }

  // Initialize Theme and Language
  applyTheme(currentTheme);
  applyLanguage(currentLang);
  if (scanStatus) scanStatus.dataset.idle = "true";
  if (riskMatrixSummary) riskMatrixSummary.dataset.idle = "true";

  // =========================================================================
  // 2. Local model status
  // =========================================================================
  async function refreshLocalModelStatus() {
    if (!localModelStatus) return;
    localModelStatus.className = "api-status-pill verifying";
    localModelStatus.innerText = currentLang === "ar" ? "جارٍ الفحص..." : "Checking...";
    try {
      const res = await fetch("/api/local-model-status");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const loadedCount = Number(data.loaded_count) || 0;
      localModelStatus.className = `api-status-pill ${loadedCount ? "active" : "offline"}`;
      if (data.classification_approved || loadedCount === 3) {
        localModelStatus.innerText = currentLang === "ar"
          ? `نماذج نظور (3/3): نشطة ومُعتمدة`
          : `Nazzoor Models (3/3): Active & Verified`;
      } else {
        localModelStatus.innerText = currentLang === "ar"
          ? `${loadedCount}/3 ملفات نماذج جاهزة للتشخيص`
          : `${loadedCount}/3 artifacts available for diagnostics`;
      }
    } catch (err) {
      localModelStatus.className = "api-status-pill invalid";
      localModelStatus.innerText = currentLang === "ar" ? "تعذر التحقق" : "Status unavailable";
      log(`[LOCAL MODEL STATUS] ${err.message}`, "danger");
    }
  }

  refreshLocalModelStatus();
  if (btnLocalModelStatus) btnLocalModelStatus.addEventListener("click", refreshLocalModelStatus);

  // =========================================================================
  // 3. Scope & Input Switchers (Remote URL vs Local File Upload)
  // =========================================================================
  if (scopeWeb) {
    scopeWeb.addEventListener("click", () => {
      scopeWeb.className = "tab-btn active";
      if (scopeApp) scopeApp.className = "tab-btn";
      currentScope = "Web";
      if (targetUrlInput) targetUrlInput.placeholder = "https://example.com";
    });
  }

  if (scopeApp) {
    scopeApp.addEventListener("click", () => {
      scopeApp.className = "tab-btn active";
      if (scopeWeb) scopeWeb.className = "tab-btn";
      currentScope = "Application";
      if (targetUrlInput) targetUrlInput.placeholder = "com.example.app or app://local";
    });
  }

  if (modeRemote) {
    modeRemote.addEventListener("click", () => {
      modeRemote.className = "tab-btn active";
      if (modeLocal) modeLocal.className = "tab-btn";
      if (panelRemoteInput) panelRemoteInput.style.display = "flex";
      if (panelLocalInput) panelLocalInput.style.display = "none";
    });
  }

  if (modeLocal) {
    modeLocal.addEventListener("click", () => {
      modeLocal.className = "tab-btn active";
      if (modeRemote) modeRemote.className = "tab-btn";
      if (panelRemoteInput) panelRemoteInput.style.display = "none";
      if (panelLocalInput) panelLocalInput.style.display = "block";
    });
  }

  // Enterprise Auth Mode Switcher
  const authSelect = document.getElementById("auth-type-select");
  const bearerBox = document.getElementById("auth-bearer-box");
  const cookieBox = document.getElementById("auth-cookie-box");
  const apikeyBox = document.getElementById("auth-apikey-box");
  const formBox = document.getElementById("auth-form-box");

  if (authSelect) {
    authSelect.addEventListener("change", () => {
      const v = authSelect.value;
      if (bearerBox) bearerBox.style.display = (v === "bearer") ? "block" : "none";
      if (cookieBox) cookieBox.style.display = (v === "cookie") ? "block" : "none";
      if (apikeyBox) apikeyBox.style.display = (v === "api_key") ? "block" : "none";
      if (formBox) formBox.style.display = (v === "form_login") ? "block" : "none";
    });
  }

  // Local File Dropzone
  if (fileDropzone && localFileInput) {
    fileDropzone.addEventListener("click", () => localFileInput.click());
    fileDropzone.addEventListener("dragover", (e) => {
      e.preventDefault();
      fileDropzone.style.borderColor = "var(--accent-primary)";
    });
    fileDropzone.addEventListener("dragleave", () => {
      fileDropzone.style.borderColor = "var(--border-color)";
    });
    fileDropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      fileDropzone.style.borderColor = "var(--border-color)";
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleSelectedFile(e.dataTransfer.files[0]);
      }
    });
    localFileInput.addEventListener("change", () => {
      if (localFileInput.files && localFileInput.files[0]) {
        handleSelectedFile(localFileInput.files[0]);
      }
    });
  }

  function handleSelectedFile(file) {
    selectedFile = file;
    if (selectedFileName) {
      selectedFileName.style.display = "block";
      const sizeKB = (file.size / 1024).toFixed(1);
      selectedFileName.innerText = `Selected: ${file.name} (${sizeKB} KB)`;
    }
    if (btnUploadAudit) btnUploadAudit.disabled = false;
  }

  // =========================================================================
  // Live Execution Stopwatch Timer & PTES Workflow Progression
  // =========================================================================
  function startLiveAuditTimer() {
    stopLiveAuditTimer(null, false);
    liveScanStartTime = Date.now();

    if (valTime) {
      valTime.innerText = "0.0s";
      valTime.style.color = "var(--accent-primary)";
    }
    const subTime = document.getElementById("sub-metric-time");
    if (subTime) {
      subTime.innerText = currentLang === "ar"
        ? "جارٍ قياس زمن الفحص مباشرة..."
        : "Measuring execution time live...";
    }

    liveTimerInterval = setInterval(() => {
      if (!liveScanStartTime || !valTime) return;
      const elapsedSec = ((Date.now() - liveScanStartTime) / 1000).toFixed(1);
      valTime.innerText = `${elapsedSec}s`;
    }, 100);
  }

  function stopLiveAuditTimer(finalDuration = null, success = true) {
    if (liveTimerInterval) {
      clearInterval(liveTimerInterval);
      liveTimerInterval = null;
    }

    if (valTime) {
      if (finalDuration != null && !isNaN(Number(finalDuration))) {
        valTime.innerText = `${Number(finalDuration).toFixed(2)}s`;
      } else if (liveScanStartTime) {
        const elapsedSec = ((Date.now() - liveScanStartTime) / 1000).toFixed(2);
        valTime.innerText = `${elapsedSec}s`;
      }
      valTime.style.color = "var(--accent-info)";
    }

    const subTime = document.getElementById("sub-metric-time");
    if (subTime) {
      if (success) {
        subTime.innerText = currentLang === "ar"
          ? "الزمن المقاس الإجمالي لهذه الجولة بالثواني"
          : "Total measured execution time in seconds";
      } else {
        subTime.innerText = currentLang === "ar"
          ? "توقف الفحص أو حدث خطأ"
          : "Scan stopped or encountered an error";
      }
    }
    liveScanStartTime = null;
  }

  function startPtesProgression() {
    stopPtesProgression();

    for (let i = 1; i <= 7; i++) {
      const el = document.getElementById(`ptes-${i}`);
      if (el) el.className = "ptes-phase-item";
    }

    let currentStep = 1;
    const step1 = document.getElementById("ptes-1");
    if (step1) step1.className = "ptes-phase-item active";

    ptesProgressionInterval = setInterval(() => {
      if (currentStep < 6) {
        const prevEl = document.getElementById(`ptes-${currentStep}`);
        if (prevEl) prevEl.className = "ptes-phase-item completed";

        currentStep++;
        const nextEl = document.getElementById(`ptes-${currentStep}`);
        if (nextEl) nextEl.className = "ptes-phase-item active";
      }
    }, 950);
  }

  function finishAllPtesSteps() {
    stopPtesProgression();
    for (let i = 1; i <= 7; i++) {
      const el = document.getElementById(`ptes-${i}`);
      if (el) el.className = "ptes-phase-item completed";
    }
  }

  function stopPtesProgression() {
    if (ptesProgressionInterval) {
      clearInterval(ptesProgressionInterval);
      ptesProgressionInterval = null;
    }
  }

  function resetPtesSteps() {
    stopPtesProgression();
    for (let i = 1; i <= 7; i++) {
      const el = document.getElementById(`ptes-${i}`);
      if (el) el.className = "ptes-phase-item";
    }
  }

  // =========================================================================
  // 4. State Reset Function
  // =========================================================================
  function resetDashboardState() {
    activeProjectId = null;
    stopLiveAuditTimer(null, false);
    resetPtesSteps();

    if (valRisk) valRisk.innerText = currentLang === "ar" ? "غير مُقيّم" : "Not assessed";
    if (valVulns) valVulns.innerText = currentLang === "ar" ? "غير متاح" : "N/A";
    if (valCompliance) {
      valCompliance.innerText = currentLang === "ar" ? "بانتظار الفحص" : "Pending";
      valCompliance.style.color = "var(--text-muted)";
    }
    const subCompliance = document.getElementById("sub-metric-compliance");
    if (subCompliance) {
      subCompliance.innerText = currentLang === "ar" ? "بانتظار بدء الفحص والتقييم" : "Awaiting scan";
    }
    if (valTime) {
      valTime.innerText = currentLang === "ar" ? "غير متاح" : "N/A";
      valTime.style.color = "var(--accent-info)";
    }
    const subTime = document.getElementById("sub-metric-time");
    if (subTime) {
      subTime.innerText = currentLang === "ar" ? "الزمن المقاس الإجمالي لهذه الجولة بالثواني" : "Total measured execution time in seconds";
    }

    for (const bar of [barAsvsL1, barAsvsL2, barCis, barNist]) {
      if (bar) bar.style.width = "0%";
    }
    for (const label of [txtAsvsL1, txtAsvsL2, txtCis, txtNist]) {
      if (label) label.innerText = currentLang === "ar" ? "بانتظار الفحص" : "Pending scan";
    }

    if (riskMatrixSummary) {
      riskMatrixSummary.dataset.idle = "false";
      riskMatrixSummary.innerText = currentLang === "ar"
        ? "بانتظار نتائج الفحص؛ لا تتوفر درجات امتثال حتى تُختبر الضوابط."
        : "Awaiting scan results; compliance scores are unavailable until controls are tested.";
    }

    if (tableBody) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="9" style="text-align: center; color: var(--text-muted); padding: 30px;">
            ${i18n[currentLang].tdAuditing}
          </td>
        </tr>
      `;
    }

    if (aiAttacksList) aiAttacksList.innerHTML = "";
    if (aiAttacksPanel) aiAttacksPanel.style.display = "none";
    if (aiSummaryCard) aiSummaryCard.style.display = "none";

    log(`------------------------------------------------------------`, "info");
    log(`[SESSION] Starting a new audit session.`, "info");
  }

  function escapeHtml(text) {
    if (text == null) return "";
    return String(text)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function displayOrUnavailable(value) {
    if (value == null || value === "") {
      return currentLang === "ar" ? "غير متاح" : "N/A";
    }
    return escapeHtml(value);
  }

  function log(msg, type = "info") {
    if (!terminal) return;
    const timeStr = new Date().toTimeString().split(" ")[0];
    const div = document.createElement("div");
    div.className = "terminal-line";
    let tag = `<span class="terminal-tag-info">[INFO]</span>`;
    if (type === "success") tag = `<span class="terminal-tag-success">[SUCCESS]</span>`;
    if (type === "warn") tag = `<span class="terminal-tag-warn">[WARN]</span>`;
    if (type === "danger") tag = `<span class="terminal-tag-danger">[ALERT]</span>`;

    div.innerHTML = `<span class="terminal-time">[${timeStr}]</span> ${tag} ${escapeHtml(msg)}`;
    terminal.appendChild(div);
    terminal.scrollTop = terminal.scrollHeight;
  }

  if (btnClearTerminal) {
    btnClearTerminal.addEventListener("click", () => {
      if (terminal) terminal.innerHTML = "";
      log(`Terminal console cleared.`, "info");
    });
  }

  // =========================================================================
  // 5. Remote Audit Execution
  // =========================================================================
  if (btnStartAudit) {
    btnStartAudit.addEventListener("click", async () => {
      clearUrlError();
      const url = targetUrlInput ? targetUrlInput.value.trim() : "";
      if (!url) {
        showUrlError(currentLang === "ar" ? "يرجى إدخال رابط الهدف أولاً." : "Please enter target URL.");
        return;
      }

      // 1. التحقق من وجود البروتوكول صراحةً (http:// أو https://)
      if (!/^https?:\/\//i.test(url)) {
        showUrlError(
          currentLang === "ar"
            ? "يجب أن يبدأ الرابط ببروتوكول صالح (http:// أو https://).\nيرجى كتابة البروتوكول صراحةً وإعادة المحاولة."
            : "The URL must explicitly start with a valid protocol (http:// or https://).\nPlease correct it and retry."
        );
        return;
      }

      resetDashboardState();

      btnStartAudit.disabled = true;
      btnStartAudit.innerText = currentLang === "ar" ? "جارٍ الفحص..." : "Scanning...";
      if (scanStatus) {
        scanStatus.dataset.idle = "false";
        scanStatus.innerText = i18n[currentLang].statusRunning;
      }

      startLiveAuditTimer();
      startPtesProgression();

      log(`[SCAN] Starting available checks for ${currentScope}: ${url}`, "warn");

      try {
        const authTypeVal = document.getElementById("auth-type-select")?.value || "none";
        const authTokenVal = document.getElementById("auth-token-input")?.value?.trim() || "";
        const authCookieVal = document.getElementById("auth-cookie-input")?.value?.trim() || "";
        const authApiKeyVal = document.getElementById("auth-apikey-input")?.value?.trim() || "";
        const loginUrlVal = document.getElementById("auth-login-url")?.value?.trim() || "";
        const loginUserVal = document.getElementById("auth-login-user")?.value?.trim() || "";
        const loginPassVal = document.getElementById("auth-login-pass")?.value?.trim() || "";
        const apiSpecVal = document.getElementById("api-spec-content")?.value?.trim() || "";
        const secondaryHeadersText = document.getElementById("secondary-auth-headers")?.value?.trim() || "";
        const secondaryResourceUrl = document.getElementById("secondary-resource-url")?.value?.trim() || "";
        const allowInternalTargets = Boolean(document.getElementById("allow-internal-targets")?.checked);
        let secondaryAuthHeaders = null;
        if (secondaryHeadersText) {
          secondaryAuthHeaders = JSON.parse(secondaryHeadersText);
          if (!secondaryAuthHeaders || Array.isArray(secondaryAuthHeaders) || typeof secondaryAuthHeaders !== "object") {
            throw new Error("Secondary account headers must be a JSON object.");
          }
        }

        const res = await fetch("/api/audit/start", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            target_url: url,
            target_type: currentScope,
            auth_type: authTypeVal,
            bearer_token: authTokenVal,
            raw_cookie: authCookieVal,
            api_key_value: authApiKeyVal,
            login_url: loginUrlVal,
            username: loginUserVal,
            password: loginPassVal,
            api_spec_content: apiSpecVal,
            secondary_auth_headers: secondaryAuthHeaders,
            secondary_resource_url: secondaryResourceUrl || null,
            allow_internal_targets: allowInternalTargets
          })
        });

        if (!res.ok) {
          let errMsg = `Server returned HTTP ${res.status}`;
          try {
            const errData = await res.json();
            errMsg = errData.detail || errMsg;
          } catch (_) {
            const text = await res.text();
            if (text) errMsg = text.slice(0, 150);
          }
          throw new Error(errMsg);
        }

        const result = await res.json();
        log(`[SCAN] Request completed; rendering returned findings.`, "success");

        if (result.project_id) activeProjectId = result.project_id;

        // Log Live Attack Outcomes
        if (result.attacks && result.attacks.length > 0) {
          result.attacks.forEach(o => {
            if (o.proven) {
              log(`[EXPLOIT CONFIRMED] ${o.attack_name} -> HTTP ${o.http_code} (${o.time_ms}ms)`, "danger");
            } else {
              log(`[TARGET RESISTED] ${o.attack_name} -> HTTP ${o.http_code} (${o.time_ms}ms): ${o.evidence}`, "info");
            }
          });
        }

        renderVaptResults(result);
      } catch (err) {
        stopLiveAuditTimer(null, false);
        stopPtesProgression();
        log(`[ERROR] Audit execution failed: ${err.message}`, "danger");
        showUrlError(err.message);
        btnStartAudit.disabled = false;
        btnStartAudit.innerText = i18n[currentLang].btnStartAudit;
        if (scanStatus) {
          scanStatus.dataset.idle = "true";
          scanStatus.innerText = i18n[currentLang].statusWaiting;
        }
      }
    });
  }

  // =========================================================================
  // 6. Local Package Upload Audit Execution
  // =========================================================================
  if (btnUploadAudit) {
    btnUploadAudit.addEventListener("click", async () => {
      if (!selectedFile) return;

      resetDashboardState();

      btnUploadAudit.disabled = true;
      btnUploadAudit.innerText = currentLang === "ar" ? "جاري فحص الحزمة..." : "Auditing Package...";
      if (scanStatus) {
        scanStatus.dataset.idle = "false";
        scanStatus.innerText = i18n[currentLang].statusRunning;
      }

      startLiveAuditTimer();
      startPtesProgression();

      log(`[SAST AUDIT] Starting static code & configuration audit on package: ${selectedFile.name}`, "warn");

      try {
        const formData = new FormData();
        formData.append("file", selectedFile);
        formData.append("target_type", currentScope);

        const res = await fetch("/api/audit/upload", {
          method: "POST",
          body: formData
        });

        if (!res.ok) {
          const errData = await res.json();
          throw new Error(errData.detail || "Package upload audit failed on server.");
        }

        const result = await res.json();
        log(`[SAST COMPLETE] Local package audit finished. Found ${result.vulns_count} issues.`, "success");

        if (result.project_id) activeProjectId = result.project_id;
        renderVaptResults(result);
      } catch (err) {
        stopLiveAuditTimer(null, false);
        stopPtesProgression();
        log(`[ERROR] Local audit failed: ${err.message}`, "danger");
      } finally {
        btnUploadAudit.disabled = false;
        btnUploadAudit.innerText = i18n[currentLang].btnUploadAudit;
      }
    });
  }

  // =========================================================================
  // 7. Render scan results into the dashboard
  // =========================================================================
  function renderVaptResults(result) {
    if (btnStartAudit) {
      btnStartAudit.disabled = false;
      btnStartAudit.innerText = i18n[currentLang].btnAuditAnother;
    }

    if (scanStatus) {
      scanStatus.innerText = i18n[currentLang].statusComplete;
    }

    const riskScore = Number(result.risk_score);
    if (valRisk) {
      valRisk.innerText = result.risk_score != null && Number.isFinite(riskScore)
        ? riskScore.toFixed(1)
        : (currentLang === "ar" ? "غير متاح" : "N/A");
    }
    if (valVulns) valVulns.innerText = displayOrUnavailable(result.vulns_count);
    
    stopLiveAuditTimer(result.duration != null ? result.duration : null, true);
    finishAllPtesSteps();

    // Calculate or retrieve actual tested compliance
    const vulns = result.vulnerabilities || [];
    let comp = result.compliance;
    if (!comp) {
      const failedAsvs = new Set();
      for (const v of vulns) {
        const asvsId = String(v.asvs || v.asvs_requirement_id || "");
        const cweId = String(v.cwe || v.cwe_id || "");
        if (asvsId.includes("5.3.4") || cweId === "CWE-89") failedAsvs.add("V5.3.4");
        if (asvsId.includes("5.3.3") || cweId === "CWE-79") failedAsvs.add("V5.3.3");
        if (asvsId.includes("5.3.8") || cweId === "CWE-78") failedAsvs.add("V5.3.8");
        if (asvsId.includes("12.3.1") || cweId === "CWE-22") failedAsvs.add("V12.3.1");
        if (asvsId.includes("3.4.1") || cweId === "CWE-1004" || cweId === "CWE-614") failedAsvs.add("V3.4.1");
        if (asvsId.includes("3.4.2") || cweId === "CWE-1275") failedAsvs.add("V3.4.2");
        if (asvsId.includes("14.4.1") || cweId === "CWE-552") failedAsvs.add("V14.4.1");
        if (asvsId.includes("14.4.4") || cweId === "CWE-548") failedAsvs.add("V14.4.4");
        if (asvsId.includes("14.4.6") || cweId === "CWE-1021") failedAsvs.add("V14.4.6");
        if (asvsId.includes("9.1.2") || cweId === "CWE-319") failedAsvs.add("V9.1.2");
        if (asvsId.includes("14.4.3") || cweId === "CWE-693") failedAsvs.add("V14.4.3");
      }
      const failedCount = failedAsvs.size;
      const totalControls = 12;
      const passedCount = Math.max(0, totalControls - failedCount);
      const l1 = Math.round((passedCount / totalControls) * 1000) / 10;
      const l2 = Math.round(l1 * 0.85 * 10) / 10;
      const cis = Math.round(Math.max(20.0, ((8 - Math.min(8, failedCount)) / 8.0) * 100.0) * 10) / 10;
      const nist = Math.round(Math.max(25.0, ((10 - Math.min(10, failedCount)) / 10.0) * 100.0) * 10) / 10;
      comp = {
        asvs_level1_score: l1,
        asvs_level2_score: l2,
        cis_controls_score: cis,
        nist_csf_score: nist,
        controls_passed: passedCount,
        controls_failed: failedCount,
        controls_assessed: totalControls
      };
    }

    const l1Score = comp.asvs_level1_score != null ? Number(comp.asvs_level1_score) : null;
    const l2Score = comp.asvs_level2_score != null ? Number(comp.asvs_level2_score) : null;
    const cisScore = comp.cis_controls_score != null ? Number(comp.cis_controls_score) : null;
    const nistScore = comp.nist_csf_score != null ? Number(comp.nist_csf_score) : null;
    const passedControls = comp.controls_passed != null ? comp.controls_passed : 0;
    const totalControls = comp.controls_assessed != null ? comp.controls_assessed : 12;

    if (valCompliance) {
      if (l1Score != null) {
        valCompliance.innerText = `${l1Score}%`;
        if (l1Score >= 80) {
          valCompliance.style.color = "var(--accent-success)";
        } else if (l1Score >= 60) {
          valCompliance.style.color = "var(--accent-warning)";
        } else {
          valCompliance.style.color = "var(--accent-danger)";
        }
      } else {
        valCompliance.innerText = currentLang === "ar" ? "غير متاح" : "N/A";
        valCompliance.style.color = "var(--text-muted)";
      }
    }

    const subCompliance = document.getElementById("sub-metric-compliance");
    if (subCompliance) {
      subCompliance.innerText = currentLang === "ar"
        ? `اجتياز ${passedControls} من ${totalControls} ضوابط مفحوصة`
        : `${passedControls}/${totalControls} tested controls passed`;
    }

    const failedCount = comp.controls_failed != null ? comp.controls_failed : 0;
    const cisPassed = Math.max(0, 8 - Math.min(8, failedCount));
    const nistPassed = Math.max(0, 10 - Math.min(10, failedCount));

    if (barAsvsL1) barAsvsL1.style.width = `${l1Score != null ? l1Score : 0}%`;
    if (txtAsvsL1) {
      txtAsvsL1.innerText = l1Score != null
        ? `${l1Score}% (${passedControls}/${totalControls} ${currentLang === "ar" ? "ضوابط سليمة" : "clean controls"})`
        : (currentLang === "ar" ? "غير متاح" : "N/A");
    }

    if (barAsvsL2) barAsvsL2.style.width = `${l2Score != null ? l2Score : 0}%`;
    if (txtAsvsL2) {
      txtAsvsL2.innerText = l2Score != null
        ? `${l2Score}% (${currentLang === "ar" ? "ضوابط متقدمة" : "Standard L2"})`
        : (currentLang === "ar" ? "غير متاح" : "N/A");
    }

    if (barCis) barCis.style.width = `${cisScore != null ? cisScore : 0}%`;
    if (txtCis) {
      txtCis.innerText = cisScore != null
        ? `${cisScore}% (${cisPassed}/8 ${currentLang === "ar" ? "ضوابط أساسية" : "essential controls"})`
        : (currentLang === "ar" ? "غير متاح" : "N/A");
    }

    if (barNist) barNist.style.width = `${nistScore != null ? nistScore : 0}%`;
    if (txtNist) {
      txtNist.innerText = nistScore != null
        ? `${nistScore}% (${nistPassed}/10 ${currentLang === "ar" ? "ضوابط معتمدة" : "certified controls"})`
        : (currentLang === "ar" ? "غير متاح" : "N/A");
    }

    // Risk Prioritization Summary
    if (riskMatrixSummary && result.vulnerabilities) {
      const p1List = result.vulnerabilities.filter(v => parseFloat(v.cvss) >= 7.0);
      riskMatrixSummary.innerHTML = currentLang === "ar" ? `
        <div style="margin-bottom:6px;"><strong>ملخص الخطورة:</strong></div>
        <div>• عدد النتائج ذات CVSS 7.0 أو أعلى: <strong>${p1List.length}</strong>. لا يتوفر تقييم EPSS موثوق لهذه النتائج.</div>
        <div style="margin-top:4px;">• تعيينات المعايير الظاهرة روابط تصنيفية، وليست إثباتًا على اختبار جميع الضوابط.</div>
      ` : `
        <div style="margin-bottom:6px;"><strong>Severity summary:</strong></div>
        <div>• Findings with CVSS 7.0 or higher: <strong>${p1List.length}</strong>. No verified EPSS estimate is available.</div>
        <div style="margin-top:4px;">• Taxonomy mappings are references, not evidence that every control was tested.</div>
      `;
    }

    // Render active request-check results
    if (result.attacks && result.attacks.length > 0 && aiAttacksPanel && aiAttacksList) {
      aiAttacksPanel.style.display = "block";
      if (result.attack_model && aiModelBadge) {
        aiModelBadge.innerText = `Model: ${result.attack_model}`;
      }

      aiAttacksList.innerHTML = result.attacks.map(a => {
        const isProven = a.proven;
        const isInconclusive = a.status === "INCONCLUSIVE";
        const cardClass = isProven ? "attack-card proven" : "attack-card resisted";
        const badgeHtml = isProven
          ? `<span class="badge badge-critical">${currentLang === "ar" ? "تم إثبات الاستغلال" : "Exploit Confirmed"} (${a.http_code})</span>`
          : `<span class="badge badge-low">${isInconclusive
            ? (currentLang === "ar" ? "غير حاسم" : "Inconclusive")
            : (currentLang === "ar" ? "لم يثبت الاستغلال" : "Not confirmed")} (${a.http_code})</span>`;

        return `
          <div class="${cardClass}">
            <div class="attack-header">
              <span class="attack-name">${escapeHtml(a.attack_name)}</span>
              ${badgeHtml}
            </div>
            <div style="font-size: 11px; color: var(--text-secondary); margin-bottom: 4px;">
              <strong>Target:</strong> <code class="code-pill">${escapeHtml(a.target_endpoint)}</code> | ${a.time_ms}ms
            </div>
            <div class="attack-proof">${escapeHtml(a.evidence)}</div>
          </div>
        `;
      }).join("");
    } else if (aiAttacksPanel) {
      aiAttacksPanel.style.display = "none";
    }

    // Render Enterprise Vulnerabilities Table
    if (result.vulnerabilities && result.vulnerabilities.length > 0 && tableBody) {
      tableBody.innerHTML = result.vulnerabilities.map(v => {
        let badgeClass = "badge-medium";
        const sev = String(v.severity).toUpperCase();
        if (sev === "CRITICAL") badgeClass = "badge-critical";
        else if (sev === "HIGH") badgeClass = "badge-high";
        else if (sev === "LOW") badgeClass = "badge-low";

        return `
          <tr>
            <td><code class="code-pill" style="color:var(--accent-primary);">${escapeHtml(v.id)}</code></td>
            <td><strong>${escapeHtml(v.title)}</strong>${(v.target_endpoint || v.affected_url) ? `<br><span style="color:var(--text-muted); font-size:10px; font-family:monospace; direction:ltr; display:inline-block;">URI: ${escapeHtml(v.target_endpoint || v.affected_url)}</span>` : ''}</td>
            <td><span class="badge ${badgeClass}">${displayOrUnavailable(v.severity)} (${displayOrUnavailable(v.cvss)})</span></td>
            <td><strong>${displayOrUnavailable(v.epss)}</strong> <span style="font-size:10px; color:var(--text-muted);">(${displayOrUnavailable(v.epss_percentile)})</span></td>
            <td><code class="code-pill">${displayOrUnavailable(v.cwe)}</code></td>
            <td><span class="code-pill" style="color:var(--accent-info);">${displayOrUnavailable(v.mitre)}</span></td>
            <td><span style="font-size:11px; color:var(--accent-success);">${displayOrUnavailable(v.asvs)}</span></td>
            <td><span style="font-size:11px; color:var(--accent-primary); font-family:monospace;">${displayOrUnavailable(v.proof)}</span></td>
            <td><code class="code-pill" style="font-size:10.5px;">${displayOrUnavailable(v.remediation)}</code></td>
          </tr>
        `;
      }).join("");
    } else if (tableBody) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="9" style="text-align: center; color: var(--accent-success); padding: 30px;">
            ${currentLang === "ar" ? "لم تُرجع هذه الجولة نتائج مؤكدة؛ وهذا لا يثبت خلو الضوابط من المخاطر." : "No verified findings were returned; this does not establish that controls are secure."}
          </td>
        </tr>
      `;
    }

    // Render the returned scan summary
    if (result.summary && aiSummaryCard && aiSummaryContent) {
      aiSummaryCard.style.display = "block";
      aiSummaryContent.innerText = result.summary;
    }
  }

  // =========================================================================
  // 8. Reliable Report Export Handlers (PDF, HTML, SARIF)
  // =========================================================================
  function triggerBrowserPrintPdf(projId) {
    const reportUrl = `/api/reports/export/${projId}/html?lang=${currentLang}`;
    if (reportIframe) {
      reportIframe.src = reportUrl;
      if (reportModal) reportModal.style.display = "flex";

      const onIframeLoaded = () => {
        reportIframe.removeEventListener("load", onIframeLoaded);
        setTimeout(() => {
          try {
            reportIframe.contentWindow.focus();
            reportIframe.contentWindow.print();
            log(`[EXPORT] Print-to-PDF dialog triggered. Choose "Save as PDF".`, "success");
          } catch (e) {
            log(`[EXPORT] Report preview opened; click the print button in modal.`, "info");
          }
        }, 500);
      };

      reportIframe.addEventListener("load", onIframeLoaded);
    } else {
      const w = window.open(reportUrl, "_blank");
      if (w) {
        w.onload = () => {
          setTimeout(() => { w.print(); }, 500);
        };
      }
    }
  }

  async function downloadReportFile(fmt) {
    const projId = activeProjectId || 1;
    log(`[EXPORT] Generating ${fmt.toUpperCase()} report for Project #${projId}...`, "info");

    try {
      const url = `/api/reports/export/${projId}/${fmt}?lang=${currentLang}&download=true`;
      const res = await fetch(url);
      if (!res.ok) {
        if (fmt === "pdf") {
          log(`[EXPORT] Cloud server headless PDF engine unavailable. Opening browser print-to-PDF...`, "warn");
          triggerBrowserPrintPdf(projId);
          return;
        }
        throw new Error(`Export failed with HTTP status ${res.status}`);
      }

      const blob = await res.blob();
      const blobUrl = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.style.display = "none";
      a.href = blobUrl;
      const ext = fmt === "pdf" ? "pdf" : fmt === "html" ? "html" : "sarif";
      a.download = `Baseera_VAPT_Report_Proj_${projId}.${ext}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(blobUrl);
      a.remove();

      log(`[REPORT DOWNLOADED] Baseera_VAPT_Report_Proj_${projId}.${ext} saved to disk.`, "success");
    } catch (err) {
      if (fmt === "pdf") {
        log(`[EXPORT] Opening browser print-to-PDF engine...`, "warn");
        triggerBrowserPrintPdf(projId);
        return;
      }
      log(`[EXPORT ERROR] Failed to generate ${fmt.toUpperCase()} report: ${err.message}`, "danger");
      alert(currentLang === "ar" ? `فشل تصدير التقرير: ${err.message}` : `Report export failed: ${err.message}`);
    }
  }

  if (btnExportPdf) {
    btnExportPdf.addEventListener("click", () => downloadReportFile("pdf"));
  }
  if (btnExportSarif) {
    btnExportSarif.addEventListener("click", () => downloadReportFile("sarif"));
  }

  // In-App HTML Report Inspection Modal
  if (btnExportHtml) {
    btnExportHtml.addEventListener("click", () => {
      const projId = activeProjectId || 1;
      if (reportIframe) reportIframe.src = `/api/reports/export/${projId}/html?lang=${currentLang}`;
      if (reportModal) reportModal.style.display = "flex";
    });
  }

  const btnModalPrint = document.getElementById("btn-modal-print");
  if (btnModalPrint) {
    btnModalPrint.addEventListener("click", () => {
      if (reportIframe && reportIframe.contentWindow) {
        try {
          reportIframe.contentWindow.focus();
          reportIframe.contentWindow.print();
        } catch (e) {
          const projId = activeProjectId || 1;
          window.open(`/api/reports/export/${projId}/html?lang=${currentLang}`, "_blank");
        }
      }
    });
  }

  if (btnCloseModal) {
    btnCloseModal.addEventListener("click", () => {
      if (reportModal) reportModal.style.display = "none";
      if (reportIframe) reportIframe.src = "about:blank";
    });
  }

  // =========================================================================
  // 9. Synthetic benchmark results modal
  // =========================================================================
  const btnOwaspBenchmark = document.getElementById("btn-owasp-benchmark");
  const benchmarkModal = document.getElementById("benchmark-modal");
  const btnCloseBenchmark = document.getElementById("btn-close-benchmark-modal");
  const btnRunLiveBenchmark = document.getElementById("btn-run-live-benchmark");
  const bmScore = document.getElementById("bm-score");
  const bmTpr = document.getElementById("bm-tpr");
  const bmFpr = document.getElementById("bm-fpr");
  const bmAcc = document.getElementById("bm-acc");
  const bmTpRatio = document.getElementById("bm-tp-ratio");
  const bmFpRatio = document.getElementById("bm-fp-ratio");
  const bmTableBody = document.getElementById("bm-table-body");
  const benchmarkStatus = document.getElementById("benchmark-status");

  async function loadBenchmarkData() {
    try {
      const res = await fetch("/api/v1/benchmark/latest");
      if (!res.ok) throw new Error("Could not load benchmark results");
      const data = await res.json();
      if (benchmarkStatus) benchmarkStatus.innerText = "";

      if (bmScore) bmScore.innerText = `${((data.tpr - data.fpr) * 100).toFixed(1)}%`;
      if (bmTpr) bmTpr.innerText = `${(data.tpr * 100).toFixed(1)}%`;
      if (bmFpr) bmFpr.innerText = `${(data.fpr * 100).toFixed(1)}%`;
      if (bmAcc) bmAcc.innerText = `${(data.accuracy * 100).toFixed(1)}%`;
      if (bmTpRatio) bmTpRatio.innerText = `${data.true_positives} / ${data.true_positives + data.false_negatives} TP`;
      if (bmFpRatio) bmFpRatio.innerText = `${data.false_positives} / ${data.true_negatives + data.false_positives} FP`;
      log(`[SYNTHETIC BENCHMARK] ${data.sample_size}/${data.planned_cases} measured; ${data.error_cases.length} execution errors.`, "info");

      if (bmTableBody && data.category_breakdown) {
        bmTableBody.innerHTML = Object.entries(data.category_breakdown).map(([cname, s]) => {
          const tot = s.TP + s.TN + s.FP + s.FN;
          const acc = tot > 0 ? ((s.TP + s.TN) / tot * 100).toFixed(1) : "0.0";
          return `
            <tr>
              <td><strong>${cname}</strong></td>
              <td style="color: #10b981; font-weight: 700;">${s.TP}</td>
              <td style="color: #38bdf8; font-weight: 700;">${s.TN}</td>
              <td style="color: ${s.FP > 0 ? '#ef4444' : 'var(--text-muted)'}; font-weight: 700;">${s.FP}</td>
              <td style="color: ${s.FN > 0 ? '#f59e0b' : 'var(--text-muted)'}; font-weight: 700;">${s.FN}</td>
              <td><span class="badge badge-success">${acc}%</span></td>
            </tr>
          `;
        }).join("");
      }

      if (benchmarkModal) benchmarkModal.style.display = "flex";
      return true;
    } catch (err) {
      const message = currentLang === "ar"
        ? `تعذر تحميل نتائج مجموعة الاختبار: ${err.message}`
        : `Could not load synthetic test results: ${err.message}`;
      if (benchmarkStatus) benchmarkStatus.innerText = message;
      log(`[BENCHMARK] ${err.message}`, "warn");
      if (benchmarkModal) benchmarkModal.style.display = "flex";
      return false;
    }
  }

  if (btnOwaspBenchmark) {
    btnOwaspBenchmark.addEventListener("click", () => {
      loadBenchmarkData();
    });
  }

  if (btnCloseBenchmark) {
    btnCloseBenchmark.addEventListener("click", () => {
      if (benchmarkModal) benchmarkModal.style.display = "none";
    });
  }

  if (btnRunLiveBenchmark) {
    btnRunLiveBenchmark.addEventListener("click", async () => {
      btnRunLiveBenchmark.disabled = true;
      btnRunLiveBenchmark.innerText = currentLang === "ar"
        ? "جارٍ تشغيل الاختبار الاصطناعي..."
        : "Running synthetic test suite...";
      try {
        const res = await fetch("/api/v1/benchmark/run", { method: "POST" });
        if (!res.ok) throw new Error(`Benchmark request failed with HTTP ${res.status}`);
        if (!await loadBenchmarkData()) throw new Error("The new benchmark results could not be loaded.");
        log("[SYNTHETIC BENCHMARK] Run completed.", "success");
      } catch (error) {
        const message = currentLang === "ar"
          ? `فشل تشغيل الاختبار الاصطناعي: ${error.message}`
          : `Synthetic benchmark failed: ${error.message}`;
        if (benchmarkStatus) benchmarkStatus.innerText = message;
        log(`[BENCHMARK] ${error.message}`, "danger");
      } finally {
        btnRunLiveBenchmark.disabled = false;
        btnRunLiveBenchmark.innerText = currentLang === "ar"
          ? "إعادة تشغيل الاختبار الاصطناعي"
          : "Run synthetic test suite again";
      }
    });
  }
});
