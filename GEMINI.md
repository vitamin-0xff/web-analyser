## Gemini Project Guidelines: Website Technology Fingerprinting CLI

This document provides a summary of the project's goals, architecture, and conventions to guide development.

### 1. Core Objective

The primary goal is to build a passive technology-fingerprinting engine that analyzes websites to identify their underlying technologies. Given a URL, the tool inspects HTTP headers, HTML, JavaScript, DNS, and TLS metadata to produce a structured list of detected technologies with confidence scores.

### 2. Architecture

The project follows a modular architecture:

-   `cli/`: Command-line interface entry point.
-   `core/`: Orchestration engine and core logic.
-   `fetch/`: Modules for fetching data (HTTP, DNS, TLS).
-   `analyzers/`: Components that analyze different parts of the fetched data (headers, HTML, etc.).
-   `rules/`: Declarative, data-driven detection rules in YAML format.
-   `models/`: Data structures for detections and technologies.
-   `output/`: Formatters for presenting the results (e.g., JSON, table).

### 3. Key Design Principles

-   **Single Responsibility:** Each module has a single, well-defined purpose. For example, `fetch/` modules only fetch data, and `analyzers/` modules only analyze it.
-   **Loose Coupling:** Modules interact through a shared, immutable `ScanContext` object, avoiding direct dependencies.
-   **Open-Closed Principle:** New technologies can be added by creating new YAML rules in the `rules/` directory without modifying the source code.
-   **Deterministic Execution:** The tool must produce the same output for the same input, with no randomness.

### 4. Detection Strategy

-   **Detection "Hits":** The engine relies on multiple weak signals (hits) to build confidence, rather than a single strong indicator.
-   **Hit Types:** Supported hit types include `header`, `cookie`, `html_pattern`, `js_global`, `script_src`, `meta_tag`, `response_body`, `tls_issuer`, and `dns_record`.
-   **Confidence Scoring:** Each hit has a weight, and the total confidence score for a detected technology is the sum of the weights of the corresponding hits (capped at 1.0).

### 5. `ScanContext`

A central, immutable `ScanContext` dataclass holds all the data fetched for a target URL. This object is passed to all analyzers to ensure that they are pure functions without side effects.

### 6. CLI Usage

-   **Input:** The CLI should accept a single URL, a file containing multiple URLs, or input from standard input (stdin).
-   **Output:** Supports different output formats, with `--json` being a key option.
-   **Flags:** Common flags include `--confidence-threshold` to filter results and `--categories` to specify which technology categories to scan for.

### 7. Version Control (Git)

-   All new features or bug fixes should be developed in a separate branch.
-   Branches should be merged into the main branch only after all tests pass.

### 8. Inspiration

The project is inspired by existing tools like **Wappalyzer**. The goal is to act as a passive, modular, and deterministic fingerprinting engine.
