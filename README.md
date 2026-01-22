## 1. Project Overview

This project is a **sample Threat Detection Engine** built to demonstrate how **unit testing can be effectively applied to security-style business logic**.

The system simulates a security SDK that:

* Receives environment signals (tags)
* Detects security threats
* Calculates overall risk severity
* Decides mitigation action (allow, dialog, block, crash)
* Produces a final threat report

The main objective of this project is to:

> Separate business logic from platform-specific dependencies and validate core logic using fast, reliable JVM-based unit tests.

**Special Handling for Clean Devices:**
If no threat tags are detected, the system performs a **silent allow** operation without showing any warning dialog.

---

## 3. Package Structure and Responsibilities

The project follows a layered architecture to improve modularity and testability.

---

### domain Package (Data Layer)

Contains only **plain data models and enums** with no business logic.

#### Action.java

Defines mitigation actions supported by the system:

* ALLOW — Silent allow when no threats are detected
* DIALOG_SKIP — Show warning and allow continuation
* BLOCKED — Restrict application usage
* CRASH — Terminate application

---

#### Severity.java

Defines severity levels used for risk classification:

* LOW
* HIGH
* CRITICAL

---

#### Threat.java

Represents a detected threat and stores:

* Threat tag (example: FRIDA, ROOTED)
* Assigned severity level

---

#### ThreatReport.java

Final output object returned by the system. Contains:

* List of detected threats
* Overall severity
* Final action decision

---

### engine Package (Core Logic Layer)

Contains the main detection and policy logic.

---

#### ThreatCatalog.java

Maintains the centralized mapping between:

```
Threat Tag → Severity Level
```

Acts as the rule source for threat classification.

---

#### ThreatEngine.java

Responsible for:

* Converting input tags into Threat objects
* Filtering unknown tags
* Calculating the highest severity among detected threats

Implements the core detection algorithm.

---

#### ThreatPolicy.java

Applies policy rules that convert severity into final action:

* LOW → DIALOG_SKIP (only when threats exist)
* HIGH → BLOCKED
* CRITICAL → CRASH

Final decision logic is applied by the service layer to ensure clean devices are silently allowed.

---

### signals Package (Input Abstraction Layer)

---

#### SignalProvider.java

Interface defining how environment signals are collected.

Allows:

* Real implementations to fetch device data
* Mock implementations to inject test data

Enables isolation of external dependencies.

---

#### StaticSignalProvider.java

Simple implementation that returns predefined tags.

Used for:

* Sample execution
* Manual testing
* Demonstration purposes

---

### service Package (Orchestration Layer)

---

#### ThreatService.java

Acts as the main entry point of the system.

Coordinates the full workflow:

1. Collects tags from SignalProvider
2. Detects threats using ThreatEngine
3. If **no threats are detected**, returns **ALLOW action silently**
4. Otherwise computes overall severity
5. Applies policy using ThreatPolicy
6. Returns a ThreatReport

External callers interact only with this class.

---

## 📊 Test Case Excel Sheet

[https://docs.google.com/spreadsheets/d/1h_XgJuF0T7a9H2HWv41TYTIylew7B3DYM3-mS8u-5hQ/edit?usp=sharing](https://docs.google.com/spreadsheets/d/1h_XgJuF0T7a9H2HWv41TYTIylew7B3DYM3-mS8u-5hQ/edit?usp=sharing)
