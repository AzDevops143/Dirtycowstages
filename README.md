# Linux Kernel Exploit Evolution (2016-2026)

> **IEEE Research Repository** | IIT Jodhpur, SAIDE

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Paper: IEEE](https://img.shields.io/badge/Paper-IEEE%20Submission-red.svg)]()
[![Affiliation: IIT Jodhpur](https://img.shields.io/badge/IIT-Jodhpur-orange.svg)](https://iitj.ac.in)
[![Docker](https://img.shields.io/badge/Docker-Testbed-2496ED?logo=docker)](docker-compose.yml)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-green.svg)](scripts/)

---

## Associated Paper

**"Page-Cache Corruption Primitives: Evolution of Linux Kernel Local Privilege Escalation (2016-2026)"**

*Charantej, Atreyee, Nidhi, Prof. Sushil*  
*SAIDE (School of Artificial Intelligence and Data engineering), IIT Jodhpur*  
*Submitted to: [IEEE Conference Name] 2026*

> Note: Citation information and DOI will be provided after the paper is accepted.

---

## Introduction

The materials in this repository support our IEEE paper submission. We provide the testing environment, analysis scripts, and isolated Docker setups used to study five specific Linux kernel local privilege escalation (LPE) vulnerabilities discovered over the past ten years.

| CVE Number    | Common Name | Year | Affected Subsystem | Exploit Reliability | Container Escape | Base Score |
|---------------|-------------|------|--------------------|---------------------|------------------|------------|
| CVE-2016-5195 | Dirty COW   | 2016 | Virtual Memory     | ~30% (race)         | No               | 7.8        |
| CVE-2022-0847 | Dirty Pipe  | 2022 | File System        | 100%                | No               | 7.8        |
| CVE-2026-31431| Copy Fail   | 2026 | Crypto AF_ALG      | Deterministic       | Yes              | 7.8        |
| CVE-2026-43284| Dirty Frag  | 2026 | Net XFRM/IPsec     | Deterministic       | Yes              | 7.8        |
| CVE-2026-46300| Fragnesia   | 2026 | XFRM ESP-in-TCP    | Deterministic       | Yes              | 7.8        |

---

## Getting Started

```bash
# 1. Clone the project locally
git clone https://github.com/YOUR_USERNAME/linux-kernel-exploit-evolution
cd linux-kernel-exploit-evolution

# 2. Start the analysis environment
docker-compose up --build

# 3. Run the orchestration script to generate the results
python3 scripts/orchestrate.py
```

The script will dump its final analysis into `results/analysis_output.json`.

---

## Project Layout

```
linux-kernel-exploit-evolution/
├── docker-compose.yml          # Container definitions for each CVE
├── docker/                     # Environment definitions
│   ├── Dockerfile.orchestrator
│   ├── Dockerfile.dirtycow
│   ├── Dockerfile.dirtypipe
│   ├── Dockerfile.copyfail
│   ├── Dockerfile.dirtyfrag
│   ├── Dockerfile.fragnesia
│   └── Dockerfile.tracer       # Tracing via eBPF
├── scripts/
│   ├── orchestrate.py          # Central analysis controller
│   └── generate_pdf.py         # Formats the IEEE PDF
├── analysis/                   # Technical breakdown of each vulnerability
├── docs/
│   └── report.html             # Viewable HTML summary
├── results/                    # Output directory (ignored by git)
│   └── analysis_output.json
└── RESEARCH_PROMPT.md          # Prompts used for generating paper drafts
```

---

## Primary Observations

1. **Shift in Reliability:** Exploit success rates shifted from being largely race-condition dependent in 2016 (Dirty COW) to completely deterministic by 2026.
2. **Target Surface Changes:** Attackers moved from targeting the virtual memory subsystem to the file system, and eventually to crypto and networking modules.
3. **Shared Mechanism:** Page-cache corruption remains the underlying root cause for all five vulnerabilities studied.
4. **Faster Discovery:** Artificial intelligence tools like Xint Code and Zellic significantly reduced the time needed to find these bugs.
5. **Patch Risks:** In the case of Fragnesia, the patch intended to fix Dirty Frag actually introduced a new vulnerability.
6. **Containerization Risks:** Every CVE analyzed from 2026 demonstrates the ability to break out of containerized environments.

---

## Ethics and Disclosure

Our team followed strict ethical guidelines during this research:

- **Simulation Only:** We only simulated the properties of these vulnerabilities. No actual kernel exploitation was carried out.
- **Public Vulnerabilities:** Every CVE included in our study has already been disclosed and patched by the respective vendors.
- **Goal:** The sole purpose of this work is to strengthen Linux kernel defenses rather than provide attack methodologies.
- **Institutional Review:** All work complies with the research ethics policies at IIT Jodhpur.

> Notice: There is no working exploit code in this repository. We only provide the scaffolding necessary to study the documented behavior of these bugs.

---

## Licensing Information

- The scripts and testbed configurations fall under the [MIT License](LICENSE).
- The text of the paper and written analysis are licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

---

## Reach Out

- For research-related questions, email: `{author}@iitj.ac.in`
- Academic Supervisor: Prof. [Name], SAIDE, IIT Jodhpur
