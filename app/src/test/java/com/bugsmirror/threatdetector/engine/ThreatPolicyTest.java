package com.bugsmirror.threatdetector.engine;

import com.bugsmirror.threatdetector.domain.Action;
import com.bugsmirror.threatdetector.domain.Severity;

import org.junit.Test;

import static org.junit.Assert.*;

public class ThreatPolicyTest {

    private final ThreatPolicy policy = new ThreatPolicy();

    @Test
    public void decideAction_whenLowSeverity_returnsDialogSkip() {

        Action action = policy.decideAction(Severity.LOW);

        assertEquals(Action.DIALOG_SKIP, action);
    }

    @Test
    public void decideAction_whenHighSeverity_returnsBlocked() {

        Action action = policy.decideAction(Severity.HIGH);

        assertEquals(Action.BLOCKED, action);
    }

    @Test
    public void decideAction_whenCriticalSeverity_returnsCrash() {

        Action action = policy.decideAction(Severity.CRITICAL);

        assertEquals(Action.CRASH, action);
    }

    @Test
    public void decideAction_whenSeverityNull_returnsSafeDefault() {

        Action action = policy.decideAction(null);

        assertEquals(Action.DIALOG_SKIP, action);
    }
}

