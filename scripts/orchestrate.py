#!/usr/bin/env python3
"""
Linux Kernel Exploit Evolution — Research Orchestrator
IEEE Paper: "Page-Cache Corruption Primitives: A Decade of Linux LPE"
IIT Jodhpur Security Research Group

This script simulates analysis of each CVE's properties in a 
controlled research environment (no actual exploitation).
"""

import json
import time
import datetime
from dataclasses import dataclass, asdict
from typing import List
import os

# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class ExploitProfile:
    cve_id: str
    name: str
    year: int
    subsystem: str
    kernel_component: str
    primitive: str
    reliability: str
    race_condition: bool
    kernel_offsets_needed: bool
    exploit_size_bytes: int
    cvss_score: float
    affects_containers: bool
    patched_date: str
    discovery_method: str
    notes: str

@dataclass
class AnalysisResult:
    profile: ExploitProfile
    page_cache_write: bool
    cow_bypass: bool          # Copy-on-Write bypass
    privilege_escalation: str
    mitigation_effectiveness: dict
    detection_signatures: List[str]
    timestamp: str

# ─── CVE Database ─────────────────────────────────────────────────────────────

CVE_DATABASE = [
    ExploitProfile(
        cve_id="CVE-2016-5195",
        name="Dirty COW",
        year=2016,
        subsystem="Virtual Memory",
        kernel_component="mm/memory.c (copy-on-write path)",
        primitive="Race condition → arbitrary page write",
        reliability="Low (race window, often needs retries)",
        race_condition=True,
        kernel_offsets_needed=False,
        exploit_size_bytes=4096,
        cvss_score=7.8,
        affects_containers=False,
        patched_date="2016-10-18",
        discovery_method="Manual code review",
        notes="9-year-old bug; notoriously slow and can crash system"
    ),
    ExploitProfile(
        cve_id="CVE-2022-0847",
        name="Dirty Pipe",
        year=2022,
        subsystem="Pipe/File System",
        kernel_component="fs/pipe.c (pipe_write)",
        primitive="Uninitialized PIPE_BUF_FLAG_CAN_MERGE → page cache write",
        reliability="High (100% reliable for LPE)",
        race_condition=False,
        kernel_offsets_needed=False,
        exploit_size_bytes=2048,
        cvss_score=7.8,
        affects_containers=False,
        patched_date="2022-03-07",
        discovery_method="Manual audit of pipe buffer flags",
        notes="Version-specific (5.8+); elegant single-path exploit"
    ),
    ExploitProfile(
        cve_id="CVE-2026-31431",
        name="Copy Fail",
        year=2026,
        subsystem="Crypto API (AF_ALG)",
        kernel_component="crypto/algif_aead.c (authencesn template)",
        primitive="Logic flaw → deterministic 4-byte page-cache write",
        reliability="Deterministic (single 732-byte Python script, cross-distro)",
        race_condition=False,
        kernel_offsets_needed=False,
        exploit_size_bytes=732,
        cvss_score=7.8,
        affects_containers=True,
        patched_date="2026-04-29",
        discovery_method="AI-assisted (Xint Code, ~1 hour scan)",
        notes="All kernels since 2017; container escape possible"
    ),
    ExploitProfile(
        cve_id="CVE-2026-43284",
        name="Dirty Frag",
        year=2026,
        subsystem="Networking (IPsec/XFRM)",
        kernel_component="net/xfrm/xfrm_input.c + net/rxrpc",
        primitive="Page frag CoW bypass via ESP+RxRPC chain",
        reliability="Deterministic (no race, no offsets)",
        race_condition=False,
        kernel_offsets_needed=False,
        exploit_size_bytes=1500,
        cvss_score=7.8,
        affects_containers=True,
        patched_date="2026-05-07",
        discovery_method="Manual research (Hyunwoo Kim)",
        notes="Chains two CVEs; affects ESP4/ESP6 + RxRPC modules"
    ),
    ExploitProfile(
        cve_id="CVE-2026-46300",
        name="Fragnesia",
        year=2026,
        subsystem="Networking (XFRM/ESP-in-TCP)",
        kernel_component="net/xfrm/xfrm_input.c (skb_try_coalesce path)",
        primitive="SKBFL_SHARED_FRAG flag not propagated → page-cache write",
        reliability="Deterministic (public PoC overwrites /usr/bin/su)",
        race_condition=False,
        kernel_offsets_needed=False,
        exploit_size_bytes=2200,
        cvss_score=7.8,
        affects_containers=True,
        patched_date="2026-05-13",
        discovery_method="AI-assisted (Zellic AI tool, William Bowling)",
        notes="Accidentally activated by Dirty Frag patch; 3rd LPE in 2 weeks"
    ),
]

# ─── Analysis Engine ──────────────────────────────────────────────────────────

def analyze_exploit(profile: ExploitProfile) -> AnalysisResult:
    """Analyze exploit characteristics for research documentation."""
    
    # Mitigation effectiveness assessment
    mitigation_map = {
        "CVE-2016-5195": {
            "SMEP/SMAP": "Partial",
            "SELinux": "Partial",
            "Kernel_Patch": "Full",
            "Module_Blacklist": "N/A"
        },
        "CVE-2022-0847": {
            "SMEP/SMAP": "No",
            "SELinux": "Partial",
            "Kernel_Patch": "Full",
            "Module_Blacklist": "N/A"
        },
        "CVE-2026-31431": {
            "SMEP/SMAP": "No",
            "SELinux": "No",
            "Kernel_Patch": "Full",
            "Module_Blacklist": "Full (disable algif_aead)"
        },
        "CVE-2026-43284": {
            "SMEP/SMAP": "No",
            "SELinux": "No",
            "Kernel_Patch": "Full",
            "Module_Blacklist": "Full (disable xfrm_algo, rxrpc)"
        },
        "CVE-2026-46300": {
            "SMEP/SMAP": "No",
            "SELinux": "No",
            "Kernel_Patch": "Full",
            "Module_Blacklist": "Full (same as Dirty Frag)"
        },
    }

    # Detection signatures (eBPF / audit rules)
    detection_map = {
        "CVE-2016-5195": [
            "audit: ptrace(PTRACE_POKEDATA) on /proc/self/mem",
            "inotify: rapid /proc/self/mem writes",
            "mmap + madvise(MADV_DONTNEED) loop detection"
        ],
        "CVE-2022-0847": [
            "audit: splice() into read-only fd",
            "page_cache_write to non-writable mapping",
            "pipe_write with PIPE_BUF_FLAG_CAN_MERGE on read-only page"
        ],
        "CVE-2026-31431": [
            "audit: AF_ALG socket open by unprivileged user",
            "algif_aead + splice() combination syscall sequence",
            "page cache modification without mmap write permission"
        ],
        "CVE-2026-43284": [
            "xfrm_input coalesce path page-cache write",
            "ESP fragment reassembly touching page-cache backed pages",
            "rxrpc + splice() cross-subsystem write pattern"
        ],
        "CVE-2026-46300": [
            "skb_try_coalesce without SKBFL_SHARED_FRAG propagation",
            "ESP-in-TCP socket + splice() to read-only file",
            "xfrm_input path triggering page-cache dirty bit"
        ],
    }

    return AnalysisResult(
        profile=profile,
        page_cache_write=True,
        cow_bypass=True,
        privilege_escalation="root (uid 0)",
        mitigation_effectiveness=mitigation_map.get(profile.cve_id, {}),
        detection_signatures=detection_map.get(profile.cve_id, []),
        timestamp=datetime.datetime.utcnow().isoformat()
    )


def generate_comparative_table(results: List[AnalysisResult]) -> dict:
    """Generate comparison table for IEEE paper."""
    return {
        "title": "Comparative Analysis of Linux Kernel LPE Exploit Chain (2016–2026)",
        "metrics": [
            {
                "cve": r.profile.cve_id,
                "name": r.profile.name,
                "year": r.profile.year,
                "subsystem": r.profile.subsystem,
                "race_free": not r.profile.race_condition,
                "cross_distro": True,
                "container_escape": r.profile.affects_containers,
                "exploit_bytes": r.profile.exploit_size_bytes,
                "cvss": r.profile.cvss_score,
                "ai_discovered": "AI" in r.profile.discovery_method,
                "patch_days": _patch_days(r.profile),
            }
            for r in results
        ]
    }


def _patch_days(profile: ExploitProfile) -> int:
    """Days from disclosure to patch (approximate)."""
    patch_map = {
        "CVE-2016-5195": 1,     # Emergency patch
        "CVE-2022-0847": 2,
        "CVE-2026-31431": 1,
        "CVE-2026-43284": 0,    # Patch same day
        "CVE-2026-46300": 0,
    }
    return patch_map.get(profile.cve_id, -1)


def generate_evolution_insights(results: List[AnalysisResult]) -> List[str]:
    """Key findings for IEEE paper."""
    return [
        "FINDING 1: Exploit reliability went from being mostly a gamble due to race conditions in 2016 to completely deterministic by 2026.",

        "FINDING 2: The vulnerable area shifted across three different kernel subsystems over time. We saw a move from Virtual Memory in 2016 to the File System by 2022, and finally to Crypto and Networking by 2026.",

        "FINDING 3: We noticed that all of the 2026 LPEs rely on the same page-cache corruption method, which points to strict page-cache write auditing as a potential unified defense.",

        "FINDING 4: Using AI assistants like Xint Code and Zellic dropped the time needed to find these vulnerabilities down to roughly an hour. This is a massive change compared to the weeks it used to take manual researchers.",

        "FINDING 5: Breaking out of containers is now a major issue, considering all the 2026 LPEs we studied can escalate privileges in Kubernetes or CI/CD pipelines.",

        "FINDING 6: Blocking specific modules works well as a temporary fix for the 2026 CVEs, but the downside is that you have to turn off important kernel features.",

        "FINDING 7: The time it takes vendors to release patches shrank to almost zero days for the latest 2026 CVEs, showing that the kernel security response process has gotten much better.",

        "FINDING 8: Interestingly, the patch released to fix Dirty Frag is what ended up causing Fragnesia. This shows that even security updates can sometimes open up new holes.",
    ]


# ─── Main Execution ───────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("Linux Kernel Exploit Evolution — Research Orchestrator")
    print("IEEE Paper Analysis Pipeline")
    print("=" * 70)

    results = []
    for profile in CVE_DATABASE:
        print(f"\n[*] Analyzing {profile.name} ({profile.cve_id})...")
        time.sleep(0.1)
        result = analyze_exploit(profile)
        results.append(result)
        print(f"    Subsystem: {profile.subsystem}")
        print(f"    Reliability: {profile.reliability}")
        print(f"    Container threat: {'YES' if profile.affects_containers else 'No'}")
        print(f"    AI discovered: {'YES' if 'AI' in profile.discovery_method else 'No'}")

    # Comparative table
    table = generate_comparative_table(results)

    # Key findings
    insights = generate_evolution_insights(results)

    # Save results
    output = {
        "paper_metadata": {
            "title": "Page-Cache Corruption Primitives: Evolution of Linux LPE (2016–2026)",
            "venue": "IEEE",
            "affiliation": "IIT Jodhpur",
            "analysis_timestamp": datetime.datetime.utcnow().isoformat(),
        },
        "cve_analyses": [asdict(r) for r in results],
        "comparative_table": table,
        "key_findings": insights,
    }

    os.makedirs("/results", exist_ok=True)
    out_path = "/results/analysis_output.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    print("\n" + "=" * 70)
    print("KEY FINDINGS:")
    for finding in insights:
        print(f"\n  {finding}")

    print(f"\n[+] Full analysis saved to: {out_path}")
    print("=" * 70)

    return output


if __name__ == "__main__":
    main()
