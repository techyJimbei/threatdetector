package com.bugsmirror.threatdetector.engine;

import com.bugsmirror.threatdetector.domain.Severity;
import com.bugsmirror.threatdetector.domain.Threat;

import org.junit.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.*;

public class ThreatEngineTest {

    private final ThreatEngine engine = new ThreatEngine();

    @Test
    public void detectThreats_whenTagsContainKnownTags_returnsThreatList() {

        Set<String> tags = new HashSet<>(Arrays.asList(
                "USB_DEBUGGING",
                "FRIDA"
        ));

        List<Threat> threats = engine.detectThreats(tags);

        assertEquals(2, threats.size());
    }

    @Test
    public void detectThreats_whenTagsContainUnknownTag_ignoresIt() {

        Set<String> tags = new HashSet<>(Arrays.asList(
                "USB_DEBUGGING",
                "UNKNOWN_TAG"
        ));

        List<Threat> threats = engine.detectThreats(tags);

        assertEquals(1, threats.size());
        assertEquals("USB_DEBUGGING", threats.get(0).getTag());
    }

    @Test
    public void computeOverallSeverity_whenMultipleThreats_returnsHighest() {

        Threat low = new Threat("MOCK_LOCATION", Severity.LOW);
        Threat high = new Threat("ROOTED", Severity.HIGH);
        Threat critical = new Threat("FRIDA", Severity.CRITICAL);

        List<Threat> threats = Arrays.asList(low, high, critical);

        Severity result = engine.computeOverallSeverity(threats);

        assertEquals(Severity.CRITICAL, result);
    }

    @Test
    public void computeOverallSeverity_whenEmptyList_returnsLow() {

        List<Threat> threats = Arrays.asList();

        Severity result = engine.computeOverallSeverity(threats);

        assertEquals(Severity.LOW, result);
    }
}

