package com.bugsmirror.threatdetector.engine;


import com.bugsmirror.threatdetector.domain.Severity;
import com.bugsmirror.threatdetector.domain.Threat;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

public final class ThreatEngine {

    /**
     * Evaluates input tags into a list of Threats.
     * Unknown tags are ignored.
     */
    public List<Threat> detectThreats(Set<String> tags) {
        if (tags == null || tags.isEmpty()) {
            return Collections.emptyList();
        }

        List<Threat> detected = new ArrayList<>();
        for (String tag : tags) {
            Threat threat = ThreatCatalog.fromTag(tag);
            if (threat != null) {
                detected.add(threat);
            }
        }
        return detected;
    }

    /**
     * Overall severity is the highest severity among detected threats.
     * If no threats detected, returns LOW.
     */
    public Severity computeOverallSeverity(List<Threat> threats) {
        if (threats == null || threats.isEmpty()) {
            return Severity.LOW;
        }

        Severity max = Severity.LOW;
        for (Threat t : threats) {
            if (t != null && t.getSeverity() != null && t.getSeverity().isHigherThan(max)) {
                max = t.getSeverity();
            }
        }
        return max;
    }
}
