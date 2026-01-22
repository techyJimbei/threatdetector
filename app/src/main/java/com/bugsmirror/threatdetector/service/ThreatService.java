package com.bugsmirror.threatdetector.service;


import com.bugsmirror.threatdetector.domain.Action;
import com.bugsmirror.threatdetector.domain.Severity;
import com.bugsmirror.threatdetector.domain.Threat;
import com.bugsmirror.threatdetector.domain.ThreatReport;
import com.bugsmirror.threatdetector.engine.ThreatEngine;
import com.bugsmirror.threatdetector.engine.ThreatPolicy;
import com.bugsmirror.threatdetector.signals.SignalProvider;

import java.util.List;
import java.util.Set;

public class ThreatService {

    private final SignalProvider signalProvider;
    private final ThreatEngine threatEngine;
    private final ThreatPolicy threatPolicy;

    public ThreatService(SignalProvider signalProvider) {
        this.signalProvider = signalProvider;
        this.threatEngine = new ThreatEngine();
        this.threatPolicy = new ThreatPolicy();
    }

    /**
     * Main API to run detection and policy evaluation.
     */
    public ThreatReport runDetection() {

        // Step 1: collect tags
        Set<String> tags = signalProvider.getTags();

        // Step 2: detect threats
        List<Threat> detectedThreats = threatEngine.detectThreats(tags);

        // Step 3: compute severity
        Severity overallSeverity = threatEngine.computeOverallSeverity(detectedThreats);

        // Step 4: decide action
        Action action = threatPolicy.decideAction(overallSeverity);

        // Step 5: build report
        return new ThreatReport(detectedThreats, overallSeverity, action);
    }
}
