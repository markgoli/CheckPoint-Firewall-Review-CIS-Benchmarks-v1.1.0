# 🔍 Check Point Firewall CIS Benchmark Audit Script (v1.1.0)

This project provides an automated audit tool for reviewing Check Point
Firewall configurations against the **Center for Internet Security (CIS)
Benchmarks v1.1.0**.

The script analyzes exported configuration files and evaluates them
against recommended security controls, producing a structured output
that highlights compliance status and potential security gaps.

------------------------------------------------------------------------

## 🚀 Features

-   Automated CIS Benchmark compliance checks (v1.1.0)
-   Supports parsing various types of configuration files (`.txt`, `.conf`)
-   Identifies misconfigurations and deviations from best practices
-   ⚡ Lightweight and fast (pure Bash implementation)
-   Helps improve firewall security posture and audit readiness

------------------------------------------------------------------------

## 📂 Requirements

-   Linux/Unix-based system
-   Bash shell (v4+ recommended)
-   Exported Check Point configuration file\
    (e.g., from `show configuration` or equivalent)

------------------------------------------------------------------------

## ⚙️ Usage

### 1. Make the script executable

``` bash
chmod +x checkpoint_cis_audit.sh
```

### 2. Run the audit

``` bash
./checkpoint_cis_audit.sh CheckpointConfigurationsFile-Latest.txt
```

You can also use other supported formats:

``` bash
./checkpoint_cis_audit.sh config.conf
```

------------------------------------------------------------------------

## 📥 Input

The script expects a configuration file exported from a Check Point
Firewall. Configuration file formats can be:

-   `.txt`
-   `.conf`

Ensure the file contains complete and properly exported configuration
data for accurate analysis.

------------------------------------------------------------------------

## 📤 Output

The script generates a compliance html report that:

-   Indicates **PASS / FAIL / REVIEW** for each CIS control
-   Highlights insecure or non-compliant configurations
-   Provides context for what is recommended based on CIS Benchmarks.

------------------------------------------------------------------------

## 🛡️ CIS Benchmark Coverage

This tool is aligned with:

-   **CIS Check Point Firewall Benchmark v1.1.0**

Coverage may include (but is not limited to):

-   Authentication and access control settings
-   Logging and monitoring configurations
-   Network object and rulebase configurations
-   Secure management practices

------------------------------------------------------------------------

## ⚠️ Disclaimer

This script is intended for **audit and assessment purposes only**.

-   It does **not** modify firewall configurations.
-   Results should be reviewed by a qualified security professional.
-   Ensure proper authorization before auditing production systems.

------------------------------------------------------------------------

## 👨‍💻 Author

Goli Mark Wasswa
