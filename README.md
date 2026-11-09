<div align="center">

<img src="banner.svg" alt="ExactMemory Banner" width="800">

<h1>ExactMemory</h1>

<p>
  <strong>A tamper-evident, replay-resistant, rollback-resistant key-value store with transparency log, remote anchor, and portable proofs. Zero external dependencies.</strong>
</p>

<p>
  Part of the <a href="https://github.com/sciencedelicmetatech/recallspection">Recallspection</a> project · Powered by Sciencedelic Metatech.
</p>

> **Architecture:** [Synthetic Intelligence Requires Exact Memory](https://doi.org/10.5281/zenodo.23378369)  
> **AGMI Status:** Officially certified **Level L4** (10/10 attacks rejected)  
> **Normative Spec:** [RPRS-1 v2.0.0](https://github.com/sciencedelicmetatech/recallspection/blob/main/spec/rprs-1.tex)

[![AGMI](https://img.shields.io/badge/agmi-L4%20Conformant-0F4C5C)](https://agentmemoryintegrity.org/stores/recallspection-exact-anchor.html)
[![Version](https://img.shields.io/badge/version-3.3.0-blue)]()
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)]()
[![Zero Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)]()
[![Tags](https://img.shields.io/badge/tags-32--byte%20HMAC--SHA256-blue)]()
[![License](https://img.shields.io/badge/license-AGPL--3.0-green)]()
[![agmi: measured](https://img.shields.io/badge/agmi-measured-0F4C5C)](https://agentmemoryintegrity.org/stores/recallspection-exact-anchor.html)
</div>

---

## Why ExactMemory?

AI agents, audit systems, and compliance pipelines all need one thing that most storage layers do not provide: **proof that stored data has not been modified**. 

- A plain database returns whatever bytes are on disk.
- A vector store returns the nearest neighbour, whether or not it is authentic.
- A cache silently serves stale content.

**ExactMemory** answers a different question: *"Is this record still exactly what was written?"*

Every record is sealed with a 32-byte HMAC-SHA256 tag, bound to a monotonic version counter, transparency log, and optional remote anchor. 
- If a single bit flips (payload, header, or metadata), the store refuses to return it. 
- If someone replays an older valid record, the version check rejects it. 
- If the entire container is rolled back, the transparency log rejects it. 
- If the log itself is deleted, `require_log=True` rejects it. 
- If both log and container are rolled back together, the remote anchor (e.g., S3 with Object Lock) rejects it.

The library is **pure Python standard library**. It runs on Linux, macOS, Windows, and iOS. No PyTorch. No NumPy. No native extensions.

---

## Official AGMI Level L4 Conformance

This core library powers the exact memory layer that achieved **Level L4 on the Agent Memory Integrity (AGMI) benchmark**, and extends the standard with **T10: Erasure Resurrection** protection.

The AGMI suite tested ten storage-level edits. Recallspection (powered by `exactmemory`) rejected **10 out of 10** on the read path: 0 edits were served as genuine, and 0 were merely reported on audit.

| Attack | Verdict |
|---|---|
| T1 content tamper | rejected on read |
| T2 tail truncation | rejected on read |
| T3 middle deletion | rejected on read |
| T4 reordering | rejected on read |
| T5 forged insertion | rejected on read |
| T6 cross-context replay | rejected on read |
| T7 rollback replay | rejected on read |
| T8 metadata tamper | rejected on read |
| T9 snapshot rollback | rejected on read |
| **T10 erasure resurrection** | **rejected on read** |

*Note: T9 requires the remote anchor backend (S3 Object Lock) to be configured.*  
[View Official L4 Conformance Result](https://agentmemoryintegrity.org/stores/recallspection-exact-anchor.html)

### 🧪 Run the AGMI Toggle Measure Yourself

You do not have to take our word for it. You can run the exact same conformance measurement locally to prove the 10/10 rejection rate:

```bash
# Run the official AGMI self-check against your local ExactMemory instance
python -m exactmemory_recallspection.conformance.agmi_selfcheck