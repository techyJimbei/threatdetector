package com.bugsmirror.threatdetector.domain;

public enum Action {

    ALLOW,         // nothing happens if no threats are detected
    DIALOG_SKIP,   // show warning dialog, allow user to continue
    BLOCKED,       // block app usage
    CRASH          // force terminate app
}

