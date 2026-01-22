package com.bugsmirror.threatdetector.domain;

public enum Severity {

    LOW(1),
    HIGH(2),
    CRITICAL(3);

    private final int level;

    Severity(int level) {
        this.level = level;
    }

    public int getLevel() {
        return level;
    }

    public boolean isHigherThan(Severity other) {
        return this.level > other.level;
    }
}
