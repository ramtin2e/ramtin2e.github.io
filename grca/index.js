</**
 * GRCA - Client-Side Compliance Analysis
 * Handles CSV, JSON, and XLSX file uploads and runs gap analysis in the browser
 */

const GRCA = (function() {
    // NIST CSF 2.0 Control Categories
    const CONTROL_CATEGORIES = {
        'PR': 'Protect',
        'DE': 'Detect', 
        'RS': 'Respond',
        'RC': 'Recover',
        'GV': 'Govern',
        'ID': 'Identify'
    };
    
    // Tier weights for scoring
    const TIER_WEIGHTS = {
        'REQUIRED': 3,
        'DESIRED': 2,
        'NICE_TO_HAVE': 1
    };
    
    // Status mapping
    const STATUS_SCORES = {
        'Implemented': 1.0,
        'Partial': 0.5,
        'Missing': 0.0
    };
    
    // NIST CSF to MITRE ATT&CK mappings (simplified)
    const ATTACK_MAPPINGS = {
        'PR.AA-01': ['T1078', 'T1110'], // Identities
        'PR.AA-02': ['T1078'], 
        'PR.AA-03': ['T1078', 'T1110'],
        'PR.AA-04': ['T1110'],
        'PR.AA-05': ['T1078', 'TD0010'],
        'PR.DS-01': ['T1485', 'T1486'],
        'PR.DS-02': ['T1041', 'T1048'],
        'PR.DS-10': ['T1005', 'T1022'],
        'PR.PS-01': ['T1199'],
        'PR.PS-02': ['T1190'],
        'PR.PS-06': ['T1195', 'T1194'],
        'PR.IR-01': ['T1485', 'T1043'],
        'PR.IR-04': ['T1499'],
        'DE.CM-01': ['T1046', 'T1129'],
        'DE.CM-02': ['T1129'],
        'DE.CM-03': ['T1046'],
        'DE.CM-06': ['T1119', 'T1537'],
        'DE.CM-09': ['T1106', 'T1112'],
        'DE.AE-02': ['T1129'],
        'DE.AE-06': ['T1111', 'T1112'],
        'RS.MA-01': ['T1059'],
        'RS.AN-03': ['T1129', 'T1086'],
        'RS.MI-01': ['T1486', 'T1489'],
        'RS.MI-02': ['T1486'],
        'RC.RP-01': ['T1490'],
        'GV.RM-01': ['T1229'],
        'GV.SC-01': ['T1195', 'T1537'],
        'ID.RA-01': ['T1582', 'T1583']
    };
    
    // Mapping file for NIST to attack
    let nistToAttack = {};
    
    // Remediation database
    const REMEDIATION = {
        'PR.AA-01': {
            title: 'Deploy MFA for all users',
            effort: 'Low',
            timeline: '1-2 weeks',
            quickWin: true,
            steps: [
                'Select MFA provider (Okta, Duo, Azure AD)',
                'Configure MFA policies for all user groups',
                'Enroll users and run training session',
                'Monitor enrollment rates'
            ]
        },
        'PR.AA-04': {
            title: 'Validate SAML assertions',
            effort: 'Medium',
            timeline: '2-4 weeks',
            quickWin: false,
            steps: [
                'Enable SAML assertion validation',
                'Implement time drift checks',
                'Add token replay detection'
            ]
        },
        'PR.AA-05': {
            title: 'Implement RBAC model',
            effort: 'High',
            timeline: '1-2 months',
            quickWin: false,
            steps: [
                'Document current permission model',
                'Define role matrix',
                'Implement RBAC in IdP',
                'Audit existing permissions'
            ]
        },
        'PR.DS-01': {
            title: 'Encrypt file shares',
            effort: 'Medium',
            timeline: '2-3 weeks',
            quickWin: true,
            steps: [
                'Audit unencrypted file shares',
                'Enable BitLocker/file-level encryption',
                'Key management process'
            ]
        },
        'PR.DS-10': {
            title: 'Data loss prevention',
            effort: 'High',
            timeline: '1-2 months',
            quickWin: false,
            steps: [
                'Deploy DLP solution',
                'Define data classification',
                'Configure blocking rules'
            ]
        },
        'PR.PS-02': {
            title: 'Automated patch management',
            effort: 'Medium',
            timeline: '3-4 weeks',
            quickWin: true,
            steps: [
                'Select patch management tool',
                'Define patch SLA',
                'Configure auto-deployment'
            ]
        },
        'PR.PS-06': {
            title: 'Secure development lifecycle',
            effort: 'High',
            timeline: '1-2 months',
            quickWin: false,
            steps: [
                'Integrate DAST scanning',
                'Add SCA dependency scanning',
                'Security training for devs'
            ]
        },
        'PR.IR-01': {
            title: 'Network microsegmentation',
            effort: 'High',
            timeline: '1-2 months',
            quickWin: false,
            steps: [
                'Define segmentation strategy',
                'Deploy microsegmentation',
                'Test isolation policies'
            ]
        },
        'DE.CM-06': {
            title: 'Third-party monitoring',
            effort: 'Medium',
            timeline: '3-4 weeks',
            quickWin: false,
            steps: [
                'Catalog third-party integrations',
                'Deploy CSPM solution',
                'Configure alerts'
            ]
        },
        'DE.CM-09': {
            title: 'Security tool integrity monitoring',
            effort: 'Medium',
            timeline: '2-3 weeks',
            quickWin: true,
            steps: [
                'Implement file integrity monitoring',
                'Define alerting rules',
                'Configure integrity checks'
            ]
        },
        'DE.AE-06': {
            title: 'Automated alerting',
            effort: 'Medium',
            timeline: '2-3 weeks',
            quickWin: true,
            steps: [
                'Define escalation matrix',
                'Configure SOAR playbooks',
                'Integrate with communication tools'
            ]
        },
        'RS.MA-01': {
            title: 'Incident response testing',
            effort: 'High',
            timeline: '1 month',
            quickWin: false,
            steps: [
                'Schedule tabletop exercise',
                'Document lessons learned',
                'Update IR plan'
            ]
        },
        'RS.AN-03': {
            title: 'Forensic analysis capability',
            effort: 'High',
            timeline: '1-2 months',
            quickWin: false,
            steps: [
                'Deploy EDR with forensics',
                'Train incident responders',
                'Define preservation procedures'
            ]
        },
        'RS.MI-01': {
            title: 'Automated containment',
            effort: 'Medium',
            timeline: '3-4 weeks',
            quickWin: false,
            steps: [
                'Define isolation triggers',
                'Configure SOAR playbook',
                'Test containment actions'
            ]
        },
        'RS.MI-02': {
            title: 'Eradication playbooks',
            effort: 'High',
            timeline: '1-2 months',
            quickWin: false,
            steps: [
                'Document eradication procedures',
                'Create playbooks',
                'Train IR team'
            ]
        },
        'RC.RP-01': {
            title: 'Recovery testing',
            effort: 'High',
            timeline: '1 month',
            quickWin: false,
            steps: [
                'Schedule DR test',
                'Execute recovery procedures',
                'Document findings'
            ]
        },
        'GV.SC-01': {
            title: 'Vendor security assessments',
            effort: 'Medium',
            timeline: '2-3 months',
            quickWin: false,
            steps: [
                'Create assessment questionnaire',
                'Build vendor inventory',
                'Deploy automated workflows'
            ]
        },
        'ID.RA-01': {
            title: 'Vulnerability scanning program',
            effort: 'High',
            timeline: '1-2 months',
            quickWin: false,
            steps: [
                'Deploy vulnerability scanner',
                'Define scan schedule',
                'Create remediation workflow'
            ]
        }
    };
    
    // Default compliance profile
    const DEFAULT_PROFILE = {
        'PR.AA-01': 'REQUIRED',
        'PR.AA-02': 'DESIRED',
        'PR.AA-03': 'REQUIRED',
        'PR.AA-04': 'REQUIRED',
        'PR.AA-05': 'REQUIRED',
        'PR.DS-01': 'REQUIRED',
        'PR.DS-02': 'REQUIRED',
        'PR.DS-10': 'DESIRED',
        'PR.PS-01': 'DESIRED',
        'PR.PS-02': 'REQUIRED',
        'PR.PS-06': 'DESIRED',
        'PR.IR-01': 'DESIRED',
        'PR.IR-04': 'NICE_TO_HAVE',
        'DE.CM-01': 'REQUIRED',
        'DE.CM-02': 'NICE_TO_HAVE',
        'DE.CM-03': 'REQUIRED',
        'DE.CM-06': 'DESIRED',
        'DE.CM-09': 'REQUIRED',
        'DE.AE-02': 'REQUIRED',
        'DE.AE-06': 'DESIRED',
        'RS.MA-01': 'REQUIRED',
        'RS.AN-03': 'DESIRED',
        'RS.MI-01': 'REQUIRED',
        'RS.MI-02': 'REQUIRED',
        'RC.RP-01': 'REQUIRED',
        'GV.RM-01': 'DESIRED',
        'GV.SC-01': 'DESIRED',
        'ID.RA-01': 'REQUIRED'
    };
    
    /**
     * Parse CSV file content
     */
    function parseCSV(content) {
        const lines = content.trim().split('\n');
        const headers = lines[0].split(',').map(h => h.trim());
        const controls = [];
        
        for (let i = 1; i < lines.length; i++) {
            const values = parseCSVLine(lines[i]);
            if (values.length >= headers.length) {
                const control = {};
                headers.forEach((h, idx) => {
                    control[h] = values[idx];
                });
                if (control.Control_ID && control.Status) {
                    controls.push(control);
                }
            }
        }
        return controls;
    }
    
    function parseCSVLine(line) {
        const result = [];
        let current = '';
        let inQuotes = false;
        
        for (let i = 0; i < line.length; i++) {
            const char = line[i];
            if (char === '"') {
                inQuotes = !inQuotes;
            } else if (char === ',' && !inQuotes) {
                result.push(current.trim());
                current = '';
            } else {
                current += char;
            }
        }
        result.push(current.trim());
        return result;
    }
    
    /**
     * Parse JSON file content
     */
    function parseJSON(content) {
        try {
            const data = JSON.parse(content);
            // Handle various JSON structures
            if (Array.isArray(data)) {
                return data;
            } else if (data.controls) {
                return data.controls;
            } else if (data.findings) {
                return data.findings;
            }
            return [];
        } catch (e) {
            console.error('JSON parse error:', e);
            return [];
        }
    }
    
    /**
     * Analyze controls against profile
     */
    function analyzeControls(controls, profile) {
        const gaps = [];
        const implemented = [];
        const partial = [];
        
        controls.forEach(ctrl => {
            const controlId = ctrl.Control_ID || ctrl.control_id || ctrl.ID;
            const status = ctrl.Status || ctrl.status || 'Missing';
            const tier = profile[controlId] || 'DESIRED';
            
            const finding = {
                id: controlId,
                name: ctrl.Control_Name || ctrl.name || controlId,
                category: ctrl.Category || ctrl.category || getCategory(controlId),
                status: status,
                tier: tier,
                tierWeight: TIER_WEIGHTS[tier],
                severity: ctrl.Severity || ctrl.severity || 'Medium',
                notes: ctrl.Notes || ctrl.notes || ''
            };
            
            // Add ATT&CK mappings
            if (ATTACK_MAPPINGS[controlId]) {
                finding.attackTechniques = ATTACK_MAPPINGS[controlId];
            }
            
            // Add remediation
            if (REMEDIATION[controlId]) {
                finding.remediation = REMEDIATION[controlId];
            }
            
            if (status === 'Missing') {
                gaps.push(finding);
            } else if (status === 'Partial') {
                partial.push(finding);
            } else {
                implemented.push(finding);
            }
        });
        
        return { gaps, partial, implemented, all: controls };
    }
    
    /**
     * Calculate compliance scores
     */
    function calculateScores(analysis) {
        const { gaps, partial, implemented } = analysis;
        
        const total = gaps.length + partial.length + implemented.length;
        if (total === 0) {
            return { score: 0, ratedLevel: 1 };
        }
        
        // Calculate weighted scores
        let totalWeight = 0;
        let achievedWeight = 0;
        
        const all = [...gaps, ...partial, ...implemented];
        all.forEach(finding => {
            const weight = finding.tierWeight || 1;
            totalWeight += weight;
            
            let score = 0;
            if (finding.status === 'Implemented') score = 1;
            else if (finding.status === 'Partial') score = 0.5;
            
            achievedWeight += score * weight;
        });
        
        const score = total > 0 ? (achievedWeight / totalWeight) * 100 : 0;
        
        // Determine maturity level
        let ratedLevel = 1;
        if (score >= 90) ratedLevel = 5;
        else if (score >= 75) ratedLevel = 4;
        else if (score >= 55) ratedLevel = 3;
        else if (score >= 35) ratedLevel = 2;
        
        return { score: Math.round(score), ratedLevel };
    }
    
    /**
     * Generate executive summary
     */
    function generateSummary(analysis, scores) {
        const { gaps, partial } = analysis;
        
        let summary = '';
        let priority = 'P1';
        
        if (scores.ratedLevel >= 4) {
            summary = 'Strong compliance posture with minor gaps. Recommended focus on high-tier items.';
            priority = 'P3';
        } else if (scores.ratedLevel >= 3) {
            summary = 'Moderate compliance. Several gaps require attention, particularly in required controls.';
            priority = 'P2';
        } else {
            summary = 'Critical compliance gaps identified. Immediate remediation required.';
            priority = 'P1';
        }
        
        const criticalGaps = gaps.filter(g => g.tier === 'REQUIRED');
        if (criticalGaps.length > 0) {
            summary += ` ${criticalGaps.length} Required-tier controls are missing.`;
        }
        
        return {
            summary,
            priority,
            totalGaps: gaps.length + partial.length,
            criticalGaps: gaps.filter(g => g.tier === 'REQUIRED').length,
            maturityLevel: scores.ratedLevel,
            maturityLabel: ['Initial', 'Developing', 'Defined', 'Managed', 'Optimizing'][scores.ratedLevel - 1]
        };
    }
    
    /**
     * Group findings by category
     */
    function groupByCategory(analysis) {
        const groups = {};
        const all = [...analysis.gaps, ...analysis.partial, ...analysis.implemented];
        
        all.forEach(finding => {
            const cat = finding.category || 'Other';
            if (!groups[cat]) {
                groups[cat] = { Implemented: 0, Partial: 0, Missing: 0 };
            }
            groups[cat][finding.status]++;
        });
        
        return groups;
    }
    
    /**
     * Group findings by tier
     */
    function groupByTier(analysis) {
        const groups = { REQUIRED: 0, DESIRED: 0, NICE_TO_HAVE: 0 };
        const all = [...analysis.gaps, ...analysis.partial, ...analysis.implemented];
        
        all.forEach(finding => {
            const tier = finding.tier || 'DESIRED';
            if (groups[tier] !== undefined) {
                groups[tier]++;
            }
        });
        
        return groups;
    }
    
    /**
     * Get category from control ID
     */
    function getCategory(controlId) {
        if (!controlId) return 'Unknown';
        const prefix = controlId.substring(0, 2);
        return CONTROL_CATEGORIES[prefix] || 'Unknown';
    }
    
    /**
     * Identify priority based on findings
     */
    function getPriorityLevel(analysis) {
        const { gaps, partial } = analysis;
        const critical = gaps.filter(g => g.tier === 'REQUIRED').length;
        
        if (critical >= 5) return 'P1';
        if (gaps.length + partial.length >= 8) return 'P2';
        return 'P3';
    }
    
    /**
     * Main analysis function
     */
    function runAnalysis(controls, profile = DEFAULT_PROFILE) {
        const analysis = analyzeControls(controls, profile);
        const scores = calculateScores(analysis);
        const summary = generateSummary(analysis, scores);
        
        return {
            analysis,
            scores,
            summary,
            byCategory: groupByCategory(analysis),
            byTier: groupByTier(analysis),
            priority: getPriorityLevel(analysis),
            timestamp: new Date().toISOString()
        };
    }
    
    // Public API
    return {
        parseCSV,
        parseJSON,
        runAnalysis,
        DEFAULT_PROFILE,
        CONTROL_CATEGORIES,
        TIER_WEIGHTS,
        ATTACK_MAPPINGS,
        REMEDIATION
    };
})();

// Export for use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = GRCA;
}