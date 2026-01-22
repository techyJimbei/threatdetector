package com.bugsmirror.threatdetector.domain;

import java.util.List;

public class ThreatReport {

    private final List<Threat> threats;
    private final Severity overallSeverity;
    private final Action action;

    public ThreatReport(List<Threat> threats,
                        Severity overallSeverity,
                        Action action) {
        this.threats = threats;
        this.overallSeverity = overallSeverity;
        this.action = action;
    }

    public List<Threat> getThreats() {
        return threats;
    }

    public Severity getOverallSeverity() {
        return overallSeverity;
    }

    public Action getAction() {
        return action;
    }

    public boolean hasThreats() {
        return threats != null && !threats.isEmpty();
    }
}

