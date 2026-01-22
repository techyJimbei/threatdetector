package com.bugsmirror.threatdetector.domain;

public class Threat {

    private final String tag;
    private final Severity severity;

    public Threat(String tag, Severity severity) {
        this.tag = tag;
        this.severity = severity;
    }

    public String getTag() {
        return tag;
    }

    public Severity getSeverity() {
        return severity;
    }
}
