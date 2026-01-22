package com.bugsmirror.threatdetector.engine;

import com.bugsmirror.threatdetector.domain.Severity;
import com.bugsmirror.threatdetector.domain.Threat;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public final class ThreatCatalog {

    private static final Map<String, Severity> TAG_TO_SEVERITY;

    static {
        Map<String, Severity> map = new HashMap<>();

        // Your mapping:
        map.put("MOCK_LOCATION", Severity.LOW);
        map.put("SCREEN_CASTING", Severity.LOW);

        map.put("USB_DEBUGGING", Severity.HIGH);
        map.put("EMULATOR", Severity.HIGH);
        map.put("ROOTED", Severity.HIGH);
        map.put("HOOKING_FRAMEWORK", Severity.HIGH);

        map.put("FRIDA", Severity.CRITICAL);
        map.put("TAMPERED_APP", Severity.CRITICAL);

        TAG_TO_SEVERITY = Collections.unmodifiableMap(map);
    }

    private ThreatCatalog() {
        // no instances
    }

    /**
     * @return a Threat for a known tag, otherwise null.
     */
    public static Threat fromTag(String tag) {
        if (tag == null) return null;

        Severity severity = TAG_TO_SEVERITY.get(tag);
        if (severity == null) return null;

        return new Threat(tag, severity);
    }

    /**
     * Useful for tests/debugging: check if a tag is supported.
     */
    public static boolean isKnownTag(String tag) {
        return tag != null && TAG_TO_SEVERITY.containsKey(tag);
    }
}

