package com.bugsmirror.threatdetector.signals;

import java.util.Set;

public interface SignalProvider {
    Set<String> getTags();
}

