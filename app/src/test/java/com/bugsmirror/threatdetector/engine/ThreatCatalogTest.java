package com.bugsmirror.threatdetector.engine;

import com.bugsmirror.threatdetector.domain.Severity;
import com.bugsmirror.threatdetector.domain.Threat;

import org.junit.Test;

import static org.junit.Assert.*;

public class ThreatCatalogTest {

    @Test
    public void fromTag_whenKnownLowTag_returnsThreatWithLowSeverity() {
        Threat threat = ThreatCatalog.fromTag("MOCK_LOCATION");

        assertNotNull(threat);
        assertEquals("MOCK_LOCATION", threat.getTag());
        assertEquals(Severity.LOW, threat.getSeverity());
    }

    @Test
    public void fromTag_whenKnownHighTag_returnsThreatWithHighSeverity() {
        Threat threat = ThreatCatalog.fromTag("USB_DEBUGGING");

        assertNotNull(threat);
        assertEquals("USB_DEBUGGING", threat.getTag());
        assertEquals(Severity.HIGH, threat.getSeverity());
    }

    @Test
    public void fromTag_whenKnownCriticalTag_returnsThreatWithCriticalSeverity() {
        Threat threat = ThreatCatalog.fromTag("FRIDA");

        assertNotNull(threat);
        assertEquals("FRIDA", threat.getTag());
        assertEquals(Severity.CRITICAL, threat.getSeverity());
    }

    @Test
    public void fromTag_whenUnknownTag_returnsNull() {
        Threat threat = ThreatCatalog.fromTag("SOME_RANDOM_TAG");

        assertNull(threat);
    }

    @Test
    public void fromTag_whenNullTag_returnsNull() {
        Threat threat = ThreatCatalog.fromTag(null);

        assertNull(threat);
    }

    @Test
    public void isKnownTag_whenKnown_returnsTrue() {
        assertTrue(ThreatCatalog.isKnownTag("ROOTED"));
    }

    @Test
    public void isKnownTag_whenUnknown_returnsFalse() {
        assertFalse(ThreatCatalog.isKnownTag("NOT_IN_CATALOG"));
    }
}

