# IEEE Research Prompt: Linux Kernel Memory Exploit Evolution

## Primary Research Outline for the Paper

---

### Main Drafting Instructions

```
Act as a systems security researcher writing an academic paper for a major IEEE conference (like S&P, TIFS, or CCS in 2026).

The focus of this paper is to track how Linux kernel memory exploits have evolved over the 2016 to 2026 timeframe. You will specifically need to cover these five CVEs:

1. CVE-2016-5195 (Dirty COW) - Focus on the race condition in the copy-on-write virtual memory subsystem.
2. CVE-2022-0847 (Dirty Pipe) - Discuss the uninitialized pipe flags and how it achieved a 100% reliable local privilege escalation.
3. CVE-2026-31431 (Copy Fail) - Analyze the AF_ALG algif_aead 4-byte page-cache write and its deterministic nature.
4. CVE-2026-43284 / CVE-2026-43500 (Dirty Frag) - Break down the IPsec ESP/RxRPC CoW bypass.
5. CVE-2026-46300 (Fragnesia) - Explain the XFRM ESP-in-TCP skb coalescing LPE.

We want to answer four main research questions:
- RQ1: Are there structural similarities in the page-cache corruption methods used across these exploits?
- RQ2: How did the reliability of these exploits shift from being probabilistic (like Dirty COW) to completely deterministic?
- RQ3: What does the shift in targeted subsystems (from VM to crypto to networking) tell us about overlooked areas in Linux security?
- RQ4: Are our current defense mechanisms (like module blacklists, SMEP/SMAP, and SELinux) actually working against this type of attack?

For the methodology section:
- Describe our controlled Docker environment that pairs vulnerable and patched kernels.
- Mention that we reproduce each CVE in isolated containers without putting real systems at risk.
- Explain our use of eBPF probes to monitor page-cache write paths in the kernel.
- We will be comparing CVSS scores, how reliable the exploits are, and how fast vendors released patches.
- End by proposing a unified detection model that monitors page-cache integrity.

Format the output as a standard 10-page, double-column IEEE paper. It needs:
- A 150-word abstract.
- An introduction covering the threat model.
- Background information on how the Linux page-cache works.
- A technical breakdown for each CVE, including exploit flow diagrams.
- A table comparing the vulnerabilities.
- A breakdown of mitigation strategies.
- A future work section touching on AI vulnerability discovery tools (like Xint Code and Zellic AI).
- References using the IEEE citation format.
```

---

### Testbed Implementation Guide

```
Write up a design for a Docker-based test environment. The goal is to safely test and analyze a specific chain of Linux kernel LPE vulnerabilities (CVE-2016-5195, CVE-2022-0847, CVE-2026-31431, CVE-2026-43284, CVE-2026-46300).

Make sure you include:
- A separate, isolated Docker container for each CVE, pinned to the correct vulnerable kernel version.
- An eBPF layer (using bpftrace) to track system calls and page-cache activity.
- A way to automatically run the exploits and save the results as JSON.
- Containers running the patched versions for comparison.
- Strict safety measures: no network access, read-only bind mounts, and absolutely no exposure to the host kernel.
- We need to collect specific metrics: how long it takes to get root, reliability percentages, occurrences of kernel panics, and eBPF events.

The final output should give us the docker-compose.yml file, the necessary Dockerfiles, a Python script to orchestrate everything, and the JSON schema we'll use to collect the results.
```

---

### Repository Documentation

```
Draft a standard GitHub README for our academic security repository (named "linux-kernel-exploit-evolution"), which goes alongside our IEEE paper submission.

The README needs to have:
- A general overview of the project with a placeholder for the paper citation.
- A table listing the covered CVEs, their CVSS scores, and the affected subsystems.
- A quickstart guide (three commands max) to get the Docker testbed running.
- Instructions on how to use the eBPF instrumentation.
- A clear ethical disclosure statement.
- A badge showing our affiliation with IIT Jodhpur.
- Licensing info: MIT for the code and CC-BY-4.0 for the paper text.
```
