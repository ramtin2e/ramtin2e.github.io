/**
 * GRC Threat Modeler — Client-Side Analysis Engine
 * Ported from Python to JavaScript for static hosting on GitHub Pages.
 */

// ==========================================
// 1. Data Mappings & Core Logic
// ==========================================

const GRCA_ENGINE = (function() {
    const CONTROL_CATEGORIES = {
        'PR': 'Protect', 'DE': 'Detect', 'RS': 'Respond', 
        'RC': 'Recover', 'GV': 'Govern', 'ID': 'Identify'
    };
    
    const TIER_WEIGHTS = { 'REQUIRED': 3, 'DESIRED': 2, 'NICE_TO_HAVE': 1 };
    
    const STATUS_SCORES = { 'Implemented': 1.0, 'Partial': 0.5, 'Missing': 0.0 };

    // NIST CSF to MITRE ATT&CK mappings
    const ATTACK_MAPPINGS = {
        'PR.AA-01': ['T1078', 'T1110'], 'PR.AA-02': ['T1078'], 'PR.AA-03': ['T1078', 'T1110'],
        'PR.AA-04': ['T1110'], 'PR.AA-05': ['T1078', 'TD0010'], 'PR.DS-01': ['T1485', 'T1486'],
        'PR.DS-02': ['T1041', 'T1048'], 'PR.DS-10': ['T1005', 'T1022'], 'PR.PS-01': ['T1199'],
        'PR.PS-02': ['T1190'], 'PR.PS-06': ['T1195', 'T1194'], 'PR.IR-01': ['T1485', 'T1043'],
        'PR.IR-04': ['T1499'], 'DE.CM-01': ['T1046', 'T1129'], 'DE.CM-02': ['T1129'],
        'DE.CM-03': ['T1046'], 'DE.CM-06': ['T1119', 'T1537'], 'DE.CM-09': ['T1106', 'T1112'],
        'DE.AE-02': ['T1129'], 'DE.AE-06': ['T1111', 'T1112'], 'RS.MA-01': ['T1059'],
        'RS.AN-03': ['T1129', 'T1086'], 'RS.MI-01': ['T1486', 'T1489'], 'RS.MI-02': ['T1486'],
        'RC.RP-01': ['T1490'], 'GV.RM-01': ['T1229'], 'GV.SC-01': ['T1195', 'T1537'],
        'ID.RA-01': ['T1582', 'T1583']
    };

    const TACTIC_MAP = {
        'T1078': ['Initial Access', 'Persistence'], 'T1110': ['Credential Access'],
        'T1485': ['Impact'], 'T1486': ['Impact'], 'T1041': ['Exfiltration'],
        'T1048': ['Exfiltration'], 'T1005': ['Collection'], 'T1022': ['Exfiltration'],
        'T1199': ['Initial Access'], 'T1190': ['Initial Access'], 'T1195': ['Initial Access'],
        'T1194': ['Initial Access'], 'T1043': ['Command and Control'], 'T1499': ['Impact'],
        'T1046': ['Discovery'], 'T1129': ['Execution'], 'T1119': ['Collection'],
        'T1537': ['Exfiltration'], 'T1106': ['Execution'], 'T1112': ['Defense Evasion'],
        'T1111': ['Credential Access'], 'T1059': ['Execution'], 'T1086': ['Execution'],
        'T1489': ['Impact'], 'T1490': ['Impact'], 'T1229': ['Initial Access'],
        'T1582': ['Reconnaissance'], 'T1583': ['Reconnaissance']
    };

    const REMEDIATION = {
        'PR.AA-01': { title: 'Deploy MFA for all users', effort: 'Low', timeline: '1-2 weeks', quick_wins: ['Enable built-in MFA for admins'], recommendations: ['Select MFA provider', 'Configure policies', 'Enroll users'] },
        'PR.AA-05': { title: 'Implement RBAC model', effort: 'High', timeline: '1-2 months', recommendations: ['Document current permissions', 'Define role matrix', 'Implement RBAC in IdP'] },
        'PR.DS-01': { title: 'Encrypt file shares', effort: 'Medium', timeline: '2-3 weeks', quick_wins: ['Enable BitLocker on servers'], recommendations: ['Audit unencrypted shares', 'Enable file-level encryption', 'Key management process'] },
        'PR.PS-02': { title: 'Automated patch management', effort: 'Medium', timeline: '3-4 weeks', quick_wins: ['Auto-patch workstations'], recommendations: ['Select patch management tool', 'Define patch SLA', 'Configure auto-deployment'] },
        'RS.MA-01': { title: 'Incident response testing', effort: 'High', timeline: '1 month', recommendations: ['Schedule tabletop exercise', 'Document lessons learned', 'Update IR plan'] },
        'ID.RA-01': { title: 'Vulnerability scanning program', effort: 'High', timeline: '1-2 months', recommendations: ['Deploy vulnerability scanner', 'Define scan schedule', 'Create remediation workflow'] }
    };

    const DEFAULT_PROFILE = {
        'PR.AA-01': 'REQUIRED', 'PR.AA-02': 'DESIRED', 'PR.AA-03': 'REQUIRED', 'PR.AA-04': 'REQUIRED', 'PR.AA-05': 'REQUIRED',
        'PR.DS-01': 'REQUIRED', 'PR.DS-02': 'REQUIRED', 'PR.DS-10': 'DESIRED', 'PR.PS-01': 'DESIRED', 'PR.PS-02': 'REQUIRED',
        'PR.PS-06': 'DESIRED', 'PR.IR-01': 'DESIRED', 'PR.IR-04': 'NICE_TO_HAVE', 'DE.CM-01': 'REQUIRED', 'DE.CM-02': 'NICE_TO_HAVE',
        'DE.CM-03': 'REQUIRED', 'DE.CM-06': 'DESIRED', 'DE.CM-09': 'REQUIRED', 'DE.AE-02': 'REQUIRED', 'DE.AE-06': 'DESIRED',
        'RS.MA-01': 'REQUIRED', 'RS.AN-03': 'DESIRED', 'RS.MI-01': 'REQUIRED', 'RS.MI-02': 'REQUIRED', 'RC.RP-01': 'REQUIRED',
        'GV.RM-01': 'DESIRED', 'GV.SC-01': 'DESIRED', 'ID.RA-01': 'REQUIRED'
    };

    function analyze(controls, profile = DEFAULT_PROFILE) {
        const findings = [];
        let totalW = 0, achievedW = 0;
        const tierStats = { REQUIRED: { total: 0, impl: 0, partial: 0, missing: 0 }, DESIRED: { total: 0, impl: 0, partial: 0, missing: 0 }, NICE_TO_HAVE: { total: 0, impl: 0, partial: 0, missing: 0 } };
        const tacticsMap = {};

        controls.forEach(ctrl => {
            const id = ctrl.Control_ID || ctrl.control_id || ctrl.ID || 'UNK';
            const status = ctrl.Status || ctrl.status || 'Missing';
            const tier = profile[id] || 'DESIRED';
            const weight = TIER_WEIGHTS[tier] || 1;
            const score = STATUS_SCORES[status] || 0;
            
            totalW += weight;
            achievedW += score * weight;

            const t = tierStats[tier];
            t.total++;
            if (status === 'Implemented') t.impl++;
            else if (status === 'Partial') t.partial++;
            else t.missing++;

            const techs = ATTACK_MAPPINGS[id] || [];
            if (status !== 'Implemented') {
                techs.forEach(tech => {
                    const tactics = TACTIC_MAP[tech] || ['Unknown'];
                    tactics.forEach(tac => {
                        if (!tacticsMap[tac]) tacticsMap[tac] = new Set();
                        tacticsMap[tac].add(tech);
                    });
                });
            }

            findings.push({
                control_id: id,
                control_name: ctrl.Control_Name || ctrl.name || id,
                status: status,
                tier: tier,
                severity: ctrl.Severity || 'Medium',
                severity_score: ctrl.Severity === 'Critical' ? 10 : ctrl.Severity === 'High' ? 7 : 4,
                gap_factor: status === 'Missing' ? 1.0 : 0.5,
                weighted_score: Math.round(weight * score * 10) / 10,
                remediation_priority: (status === 'Missing' && tier === 'REQUIRED') ? 'P1 - Critical' : (status === 'Missing' || tier === 'REQUIRED') ? 'P2 - High' : 'P3 - Medium',
                exposed_techniques: techs,
                recommendations: REMEDIATION[id] || { recommendations: ['Conduct detailed gap assessment', 'Review framework documentation'] }
            });
        });

        const overallScore = totalW ? (achievedW / totalW) * 100 : 0;
        const roadmap = { 'P1 - Critical': 0, 'P2 - High': 0, 'P3 - Medium': 0, 'P4 - Low': 0 };
        findings.forEach(f => { if (f.status !== 'Implemented') roadmap[f.remediation_priority]++; });

        const threat_exposures = [];
        Object.entries(tacticsMap).forEach(([tac, techs]) => {
            techs.forEach(tech => {
                threat_exposures.push({ technique_id: tech, tactics: [tac], risk_level: roadmap['P1 - Critical'] > 0 ? 'Critical' : 'High', exposure_count: 1 });
            });
        });

        const maturityLevel = overallScore >= 90 ? 5 : overallScore >= 75 ? 4 : overallScore >= 55 ? 3 : overallScore >= 35 ? 2 : 1;
        const maturityLabels = ['Initial', 'Developing', 'Defined', 'Managed', 'Optimizing'];
        const maturityDescs = [
            'Security processes are ad-hoc and reactive.',
            'Basic processes are established but inconsistent.',
            'Standardized processes are documented and communicated.',
            'Processes are measured and controlled.',
            'Continuous process improvement is in place.'
        ];

        return {
            overall_compliance_score: overallScore,
            total_controls_analyzed: controls.length,
            total_gaps: findings.filter(f => f.status !== 'Implemented').length,
            critical_findings_count: findings.filter(f => f.remediation_priority === 'P1 - Critical').length,
            high_findings_count: findings.filter(f => f.remediation_priority === 'P2 - High').length,
            profile_name: 'NIST CSF 2.0 (Custom)',
            findings: findings,
            roadmap: roadmap,
            tier_summaries: {
                REQUIRED: { total_controls: tierStats.REQUIRED.total, implemented: tierStats.REQUIRED.impl, partial: tierStats.REQUIRED.partial, missing: tierStats.REQUIRED.missing, compliance_percentage: tierStats.REQUIRED.total ? Math.round((tierStats.REQUIRED.impl / tierStats.REQUIRED.total) * 100) : 0 },
                DESIRED: { total_controls: tierStats.DESIRED.total, implemented: tierStats.DESIRED.impl, partial: tierStats.DESIRED.partial, missing: tierStats.DESIRED.missing, compliance_percentage: tierStats.DESIRED.total ? Math.round((tierStats.DESIRED.impl / tierStats.DESIRED.total) * 100) : 0 },
                NICE_TO_HAVE: { total_controls: tierStats.NICE_TO_HAVE.total, implemented: tierStats.NICE_TO_HAVE.impl, partial: tierStats.NICE_TO_HAVE.partial, missing: tierStats.NICE_TO_HAVE.missing, compliance_percentage: tierStats.NICE_TO_HAVE.total ? Math.round((tierStats.NICE_TO_HAVE.impl / tierStats.NICE_TO_HAVE.total) * 100) : 0 }
            },
            threat_exposures: threat_exposures,
            executive_summary: {
                posture_rating: overallScore >= 80 ? 'Strong' : overallScore >= 50 ? 'Moderate' : 'Critical',
                overall_assessment: overallScore >= 80 ? 'The organization demonstrates a robust security posture with most critical controls in place.' : 'The organization faces significant security challenges, with key compliance gaps identified.',
                maturity: { level: maturityLevel, label: maturityLabels[maturityLevel-1], description: maturityDescs[maturityLevel-1] },
                key_findings: findings.filter(f => f.remediation_priority === 'P1 - Critical').slice(0, 3).map(f => `Missing critical control: ${f.control_name}`),
                recommendations_summary: findings.filter(f => f.remediation_priority === 'P1 - Critical').slice(0, 4).map(f => f.recommendations.title || `Remediate ${f.control_id}`)
            }
        };
    }

    return { analyze, DEFAULT_PROFILE };
})();

// ==========================================
// 2. UI & Interaction Logic
// ==========================================

let selectedFile = null;
let analysisResult = null;

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const dom = {
    dropzone: $('#dropzone'), fileInput: $('#file-input'), fileInfo: $('#file-info'),
    fileName: $('#file-name'), fileSize: $('#file-size'), fileRemove: $('#file-remove'),
    frameworkSelect: $('#framework-select'), analyzeBtn: $('#analyze-btn'), sampleButtons: $$('.sample-btn'),
    uploadSection: $('#upload-section'), resultsSection: $('#results-section'),
    backBtn: $('#back-btn'), exportBtn: $('#export-btn'),
    toast: $('#toast'), toastMessage: $('#toast-message'),
    drawerOverlay: $('#drawer-overlay'), drawer: $('#finding-drawer'), drawerClose: $('#drawer-close'),
};

document.addEventListener('DOMContentLoaded', () => {
    setupDropzone(); setupFileInput(); setupButtons(); setupDrawer();
    setupTheme(); setupFilters();
});

// ── Dropzone ──
function setupDropzone() {
    dom.dropzone.addEventListener('click', () => dom.fileInput.click());
    dom.dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dom.dropzone.classList.add('drag-over'); });
    dom.dropzone.addEventListener('dragleave', () => dom.dropzone.classList.remove('drag-over'));
    dom.dropzone.addEventListener('drop', (e) => { e.preventDefault(); dom.dropzone.classList.remove('drag-over'); if (e.dataTransfer.files.length) handleFileSelect(e.dataTransfer.files[0]); });
}
function setupFileInput() {
    dom.fileInput.addEventListener('change', (e) => { if (e.target.files.length) handleFileSelect(e.target.files[0]); });
    dom.fileRemove.addEventListener('click', () => { selectedFile = null; dom.fileInfo.classList.add('hidden'); dom.dropzone.classList.remove('hidden'); dom.analyzeBtn.disabled = true; dom.fileInput.value = ''; });
}
function handleFileSelect(file) {
    const ext = '.' + file.name.split('.').pop().toLowerCase();
    if (!['.csv','.json','.xlsx'].includes(ext)) { showToast('Unsupported format: ' + ext); return; }
    selectedFile = file;
    dom.fileName.textContent = file.name;
    dom.fileSize.textContent = formatBytes(file.size);
    dom.fileInfo.classList.remove('hidden');
    dom.dropzone.classList.add('hidden');
    dom.analyzeBtn.disabled = false;
}

// ── Buttons ──
function setupButtons() {
    dom.analyzeBtn.addEventListener('click', runFileUploadAnalysis);
    dom.backBtn.addEventListener('click', () => { dom.resultsSection.classList.add('hidden'); dom.uploadSection.classList.remove('hidden'); window.scrollTo({top:0,behavior:'smooth'}); });
    dom.exportBtn.addEventListener('click', exportJSON);
    dom.sampleButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const sampleName = btn.dataset.sample;
            if (sampleName === 'nist-csf-sample') runSampleAnalysis(NIST_SAMPLE_DATA);
        });
    });
}

// ── Analysis Execution ──
function runFileUploadAnalysis() {
    if (!selectedFile) return;
    setLoading(true);
    const reader = new FileReader();
    reader.onload = function(e) {
        let controls = [];
        try {
            const content = e.target.result;
            if (selectedFile.name.endsWith('.json')) {
                controls = JSON.parse(content);
            } else if (selectedFile.name.endsWith('.csv')) {
                const parsed = Papa.parse(content, { header: true, skipEmptyLines: true });
                controls = parsed.data;
            } else if (selectedFile.name.endsWith('.xlsx')) {
                const wb = XLSX.read(content, { type: 'binary' });
                controls = XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]]);
            }
            
            if (controls.length === 0) throw new Error('No controls found in file');
            
            setTimeout(() => {
                analysisResult = GRCA_ENGINE.analyze(controls);
                renderResults(analysisResult);
                setLoading(false);
            }, 600);
            
        } catch(err) {
            showToast('Error: ' + err.message);
            setLoading(false);
        }
    };
    if (selectedFile.name.endsWith('.xlsx')) reader.readAsBinaryString(selectedFile);
    else reader.readAsText(selectedFile);
}

function runSampleAnalysis(data) {
    setLoading(true);
    setTimeout(() => {
        analysisResult = GRCA_ENGINE.analyze(data);
        renderResults(analysisResult);
        setLoading(false);
    }, 800);
}

function setLoading(loading) {
    const t = dom.analyzeBtn.querySelector('.btn-text'), l = dom.analyzeBtn.querySelector('.btn-loader');
    dom.analyzeBtn.disabled = loading;
    if (loading) { t.classList.add('hidden'); l.classList.remove('hidden'); }
    else { t.classList.remove('hidden'); l.classList.add('hidden'); }
}

// ── Render Results ──
function renderResults(r) {
    dom.uploadSection.classList.add('hidden'); dom.resultsSection.classList.remove('hidden');
    window.scrollTo({top:0,behavior:'smooth'});
    
    // Score ring
    const score = r.overall_compliance_score;
    const circ = 2*Math.PI*52, offset = circ*(1-score/100);
    const ring = $('#score-ring-fill');
    ring.style.strokeDasharray = circ; ring.style.strokeDashoffset = circ;
    requestAnimationFrame(()=>requestAnimationFrame(()=>{ ring.style.strokeDashoffset = offset; }));
    
    const scoreEl = $('#score-value');
    scoreEl.textContent = Math.round(score);
    scoreEl.style.color = score>=75?'#2ed573':score>=40?'#ffa502':'#ff4757';
    
    animateCounter('#total-controls', r.total_controls_analyzed);
    animateCounter('#total-gaps', r.total_gaps);
    animateCounter('#critical-count', r.critical_findings_count);
    animateCounter('#high-count', r.high_findings_count);
    
    renderExecSummary(r.executive_summary);
    renderTierBreakdown(r.tier_summaries); 
    renderRoadmap(r.roadmap);
    renderDonutChart(r); 
    renderFindings(r.findings); 
    renderAttack(r.threat_exposures);
    
    $$('#results-section .card').forEach((c,i) => { c.classList.add('animate-in'); c.style.animationDelay=`${i*0.08}s`; });
}

function renderExecSummary(es) {
    const badge = $('#posture-badge');
    badge.textContent = es.posture_rating;
    badge.className = 'card-badge posture-' + es.posture_rating.toLowerCase();
    
    const mat = es.maturity;
    const matEl = $('#exec-maturity');
    let bars = '';
    for (let i = 1; i <= 5; i++) bars += `<div class="maturity-bar ${i <= mat.level ? 'active' : ''}"></div>`;
    matEl.innerHTML = `<div class="maturity-gauge">${bars}</div>
        <div class="maturity-text">
            <div class="maturity-level">Maturity Level ${mat.level}/5</div>
            <div class="maturity-label">${mat.label}</div>
            <div class="maturity-desc">${mat.description}</div>
        </div>`;
    
    $('#exec-assessment').textContent = es.overall_assessment;
    $('#exec-findings').innerHTML = (es.key_findings||[]).map(f => `<div class="exec-finding-item"><span class="exec-finding-bullet"></span><span>${f}</span></div>`).join('');
    $('#exec-recs').innerHTML = '<div style="font-weight:700;margin-bottom:0.5rem;font-size:0.75rem;text-transform:uppercase;color:var(--accent-light)">Recommended Actions</div>' +
        (es.recommendations_summary||[]).map((r,i) => `<div class="exec-rec-item"><span class="exec-rec-num">${i+1}</span><span>${r}</span></div>`).join('');
}

function renderTierBreakdown(tiers) {
    const body = $('#tier-body'); body.innerHTML = '';
    const order=['REQUIRED','DESIRED','NICE_TO_HAVE'];
    order.forEach(n => {
        const t = tiers[n]; if (!t || !t.total_controls) return;
        const total=t.total_controls, pct=t.compliance_percentage;
        const iW=total?(t.implemented/total*100):0, pW=total?(t.partial/total*100):0, mW=total?(t.missing/total*100):0;
        const row = document.createElement('div'); row.className='tier-row';
        row.innerHTML = `<span class="tier-label">${n.replace(/_/g,' ')}</span>
            <div class="tier-bar-wrap"><div class="tier-bar-segment implemented" style="width:${iW}%"></div><div class="tier-bar-segment partial" style="width:${pW}%"></div><div class="tier-bar-segment missing" style="width:${mW}%"></div></div>
            <span class="tier-pct" style="color:${pct>=70?'#2ed573':pct>=40?'#ffa502':'#ff4757'}">${pct}%</span>`;
        body.appendChild(row);
    });
}

function renderRoadmap(roadmap) {
    const body = $('#roadmap-body'); body.innerHTML = '';
    [{key:'P1 - Critical',color:'var(--critical)',label:'P1 Critical'},{key:'P2 - High',color:'var(--high)',label:'P2 High'},{key:'P3 - Medium',color:'var(--medium)',label:'P3 Medium'}].forEach(p => {
        const count = roadmap[p.key]||0;
        body.innerHTML += `<div class="roadmap-row"><span class="roadmap-label"><span class="roadmap-dot" style="background:${p.color}"></span>${p.label}</span><span class="roadmap-count" style="color:${count>0?p.color:'var(--text-muted)'}">${count}</span></div>`;
    });
}

function renderDonutChart(r) {
    const svg = $('#status-donut'); const legend = $('#donut-legend');
    svg.innerHTML = ''; legend.innerHTML = '';
    let impl=0, partial=0, missing=0;
    Object.values(r.tier_summaries).forEach(t => { impl+=t.implemented; partial+=t.partial; missing+=t.missing; });
    const total = impl+partial+missing;
    if (!total) return;
    const segments = [
        {label:'Implemented',count:impl,color:'#00D2FF'},
        {label:'Partial',count:partial,color:'#ffa502'},
        {label:'Missing',count:missing,color:'#ff4757'},
    ];
    const r2=44, cx=60, cy=60, circ=2*Math.PI*r2;
    let cumulative=0;
    segments.forEach(s => {
        if (!s.count) return;
        const pct = s.count/total;
        const circle = document.createElementNS('http://www.w3.org/2000/svg','circle');
        circle.setAttribute('cx',cx); circle.setAttribute('cy',cy); circle.setAttribute('r',r2);
        circle.setAttribute('fill','none'); circle.setAttribute('stroke',s.color); circle.setAttribute('stroke-width','14');
        circle.setAttribute('stroke-dasharray',`${pct*circ} ${circ}`);
        circle.setAttribute('stroke-dashoffset',`${-cumulative*circ}`);
        svg.appendChild(circle);
        cumulative += pct;
    });
    legend.innerHTML = segments.map(s => `<div class="donut-legend-item"><span class="donut-legend-dot" style="background:${s.color}"></span>${s.label}: <span class="donut-legend-count">${s.count}</span></div>`).join('');
}

function renderFindings(findings) {
    const tbody = $('#findings-tbody'); tbody.innerHTML = '';
    findings.forEach((f,i) => {
        const tr = document.createElement('tr');
        tr.dataset.tier = f.tier; tr.dataset.priority = f.remediation_priority;
        const sc = f.status==='Missing'?'badge-missing':f.status==='Partial'?'badge-partial':'badge-implemented';
        const tc = f.tier==='REQUIRED'?'badge-required':f.tier==='DESIRED'?'badge-desired':'badge-nice';
        const pc = f.remediation_priority.includes('P1')?'badge-p1':f.remediation_priority.includes('P2')?'badge-p2':'badge-p3';
        const techs = (f.exposed_techniques||[]).map(t=>`<span class="tech-tag">${t}</span>`).join('');
        tr.innerHTML = `<td>${i+1}</td><td style="font-weight:600;color:var(--text-primary)">${f.control_id}</td><td>${f.control_name}</td>
            <td><span class="badge ${sc}">${f.status}</span></td><td><span class="badge ${tc}">${f.tier.replace(/_/g,' ')}</span></td>
            <td>${f.severity}</td><td class="td-score">${f.weighted_score}</td>
            <td><span class="badge ${pc}">${f.remediation_priority}</span></td><td><div class="tech-tags">${techs}</div></td>`;
        tr.addEventListener('click', () => openDrawer(f));
        tbody.appendChild(tr);
    });
}

function renderAttack(exposures) {
    $('#attack-count').textContent = `${exposures.length} techniques exposed`;
    const tbody = $('#attack-tbody'); tbody.innerHTML = '';
    exposures.forEach(e => {
        const rc = `badge-risk-${e.risk_level.toLowerCase()}`;
        tbody.innerHTML += `<tr><td><span style="font-weight:600;color:var(--text-primary)">${e.technique_id}</span></td>
            <td>${e.tactics.join(', ')}</td><td><span class="badge ${rc}">${e.risk_level}</span></td><td>${e.exposure_count}</td></tr>`;
    });
}

// ── Detail Drawer ──
function setupDrawer() {
    dom.drawerClose.addEventListener('click', closeDrawer);
    dom.drawerOverlay.addEventListener('click', closeDrawer);
}
function openDrawer(f) {
    $('#drawer-control-id').textContent = f.control_id;
    $('#drawer-control-name').textContent = f.control_name;
    const sc = f.status==='Missing'?'badge-missing':f.status==='Partial'?'badge-partial':'badge-implemented';
    const tc = f.tier==='REQUIRED'?'badge-required':f.tier==='DESIRED'?'badge-desired':'badge-nice';
    const pc = f.remediation_priority.includes('P1')?'badge-p1':f.remediation_priority.includes('P2')?'badge-p2':'badge-p3';
    $('#drawer-badges').innerHTML = `<span class="badge ${sc}">${f.status}</span><span class="badge ${tc}">${f.tier.replace(/_/g,' ')}</span><span class="badge ${pc}">${f.remediation_priority}</span>`;
    $('#drawer-score-grid').innerHTML = `<div class="drawer-score-item"><div class="drawer-score-value">${f.severity_score}</div><div class="drawer-score-label">Severity</div></div>
        <div class="drawer-score-item"><div class="drawer-score-value">${f.gap_factor}</div><div class="drawer-score-label">Gap Factor</div></div>
        <div class="drawer-score-item"><div class="drawer-score-value" style="color:var(--accent-light)">${f.weighted_score}</div><div class="drawer-score-label">Weighted</div></div>`;
    $('#drawer-attack-list').innerHTML = (f.exposed_techniques||[]).map(t => `<span class="drawer-attack-tag">${t}</span>`).join('');
    
    const rem = f.recommendations;
    let html = `<div class="remediation-title-row"><span class="remediation-title-text">${rem.title || 'Baseline Remediation'}</span></div>`;
    html += `<div class="remediation-meta"><div class="remediation-meta-item"><span class="remediation-meta-label">Effort:</span><span class="remediation-meta-value">${rem.effort || 'Medium'}</span></div></div>`;
    html += `<ul class="remediation-steps">${(rem.recommendations||[]).map((r,i) => `<li class="remediation-step"><span class="remediation-step-num">${i+1}</span><span>${r}</span></li>`).join('')}</ul>`;
    if (rem.quick_wins) html += `<div class="quick-wins-section"><div class="quick-wins-title">⚡ Quick Wins</div>${rem.quick_wins.map(q => `<div class="quick-win-item">${q}</div>`).join('')}</div>`;
    $('#drawer-remediation').innerHTML = html;

    dom.drawerOverlay.classList.remove('hidden'); dom.drawer.classList.remove('hidden');
    requestAnimationFrame(() => { dom.drawerOverlay.classList.add('show'); dom.drawer.classList.add('show'); });
}
function closeDrawer() {
    dom.drawerOverlay.classList.remove('show'); dom.drawer.classList.remove('show');
    setTimeout(() => { dom.drawerOverlay.classList.add('hidden'); dom.drawer.classList.add('hidden'); }, 350);
}

// ── Helpers ──
function formatBytes(b) { return b<1024?b+' B':b<1048576?(b/1024).toFixed(1)+' KB':(b/1048576).toFixed(1)+' MB'; }
function showToast(msg) { dom.toastMessage.textContent = msg; dom.toast.classList.remove('hidden'); dom.toast.classList.add('show'); setTimeout(()=>dom.toast.classList.remove('show'), 3000); }
function animateCounter(sel, target) {
    const el = $(sel); if (!el) return;
    let curr = 0; const step = target / 30;
    const interval = setInterval(() => { curr += step; if (curr >= target) { el.textContent = target; clearInterval(interval); } else { el.textContent = Math.round(curr); } }, 20);
}
function setupTheme() {
    $('#theme-toggle').addEventListener('click', () => {
        const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
        document.documentElement.setAttribute('data-theme', isDark ? 'light' : 'dark');
        $('#theme-icon-dark').classList.toggle('hidden'); $('#theme-icon-light').classList.toggle('hidden');
    });
}
function setupFilters() {
    $('#findings-tier-filter').addEventListener('change', applyFilters);
    $('#findings-priority-filter').addEventListener('change', applyFilters);
}
function applyFilters() {
    const tier = $('#findings-tier-filter').value, prio = $('#findings-priority-filter').value;
    $$('#findings-tbody tr').forEach(tr => { tr.style.display = (!tier || tr.dataset.tier === tier) && (!prio || tr.dataset.priority === prio) ? '' : 'none'; });
}
function exportJSON() {
    if (!analysisResult) return;
    const blob = new Blob([JSON.stringify(analysisResult, null, 2)], { type: 'application/json' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = `grca_analysis_${new Date().toISOString().slice(0,10)}.json`;
    a.click();
}

// ==========================================
// 3. Sample Data
// ==========================================

const NIST_SAMPLE_DATA = [
    {Control_ID: 'PR.AA-01', Control_Name: 'Identity management', Status: 'Partial', Severity: 'Critical'},
    {Control_ID: 'PR.AA-05', Control_Name: 'Access permissions', Status: 'Missing', Severity: 'Critical'},
    {Control_ID: 'PR.DS-01', Control_Name: 'Data-at-rest protection', Status: 'Partial', Severity: 'High'},
    {Control_ID: 'PR.PS-02', Control_Name: 'Patch management', Status: 'Missing', Severity: 'Critical'},
    {Control_ID: 'DE.CM-01', Control_Name: 'Network monitoring', Status: 'Implemented', Severity: 'High'},
    {Control_ID: 'RS.MA-01', Control_Name: 'Incident response', Status: 'Missing', Severity: 'Critical'},
    {Control_ID: 'ID.RA-01', Control_Name: 'Vulnerability identification', Status: 'Missing', Severity: 'Critical'},
    {Control_ID: 'PR.DS-02', Control_Name: 'Data-in-transit protection', Status: 'Implemented', Severity: 'High'},
    {Control_ID: 'DE.CM-09', Control_Name: 'Security tool integrity', Status: 'Missing', Severity: 'Medium'}
];
