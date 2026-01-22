package com.bugsmirror.threatdetector.service;

import com.bugsmirror.threatdetector.domain.Action;
import com.bugsmirror.threatdetector.domain.ThreatReport;
import com.bugsmirror.threatdetector.signals.SignalProvider;

import org.junit.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class ThreatServiceTest {

    @Test
    public void runDetection_whenCriticalThreatPresent_returnsCrashAction() {

        // Create mock (fake provider)
        SignalProvider provider = mock(SignalProvider.class);

        // Fake tags returned by provider
        Set<String> tags = new HashSet<>();
        tags.add("FRIDA");

        when(provider.getTags()).thenReturn(tags);

        ThreatService service = new ThreatService(provider);

        ThreatReport report = service.runDetection();

        assertEquals(Action.CRASH, report.getAction());
        assertEquals(1, report.getThreats().size());

        // Verify provider was called
        verify(provider).getTags();
    }
}
