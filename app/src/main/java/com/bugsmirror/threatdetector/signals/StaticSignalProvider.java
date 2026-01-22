package com.bugsmirror.threatdetector.signals;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class StaticSignalProvider implements SignalProvider {

    private final Set<String> tags = new HashSet<>();

    public StaticSignalProvider(Set<String> initialTags) {
        if (initialTags != null) {
            tags.addAll(initialTags);
        }
    }

    @Override
    public Set<String> getTags() {
        return Collections.unmodifiableSet(tags);
    }
}

