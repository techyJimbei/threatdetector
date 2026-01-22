package com.bugsmirror.threatdetector.engine;

import com.bugsmirror.threatdetector.domain.Action;
import com.bugsmirror.threatdetector.domain.Severity;

public final class ThreatPolicy {

    public Action decideAction(Severity severity) {
        if (severity == null) {
            // safest default for unknown input in this sample:
            return Action.DIALOG_SKIP;
        }

        switch (severity) {
            case LOW:
                return Action.DIALOG_SKIP;
            case HIGH:
                return Action.BLOCKED;
            case CRITICAL:
                return Action.CRASH;
            default:
                return Action.DIALOG_SKIP;
        }
    }
}

