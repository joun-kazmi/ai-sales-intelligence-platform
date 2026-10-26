# Take-home: AI Sales Intelligence Platform (Firmable)

Role: Software Engineering Lead (~80% hands-on). Due: end of week, **Fri 2026-10-30**.

## The brief (as given)

**Context.** Imagine you're building for the sales team at a cybersecurity software company. Out of thousands of businesses in their market, which ones need cybersecurity help right now, and how do they reach them first? Your job is to turn raw company data into a tool that answers that.

**The task.** Build a small sales intelligence platform that helps a sales team find, rank and target the businesses most likely to buy cybersecurity software. Start from how B2B sales teams actually prospect, and let real use cases decide what you build.

**Dataset.** Use the provided dataset as the core of the prototype.
- This is one file. In production, hundreds to thousands of files like it arrive every month, so design ingestion and scoring to keep up with that volume.
- Look for the hidden signals. What in this data tells a salesperson "this company needs cybersecurity help"? The best ones won't jump out if you hand the file straight to an LLM. Understand what's in it yourself before you point a coding agent at it.
- Drafting outreach emails with LLM calls or designing a great UI isn't the interesting part. Spend time on the signals and what they say about each company.

**How they work.** AI is the workflow, not a tool bolted on. They look at how you build as much as what you ship, and want out-of-the-box ideas in the signals, the scoring and the dev loop. If you use LLMs, show how you know they're right and what they cost.

**Deliverables.**
1. A working, hosted app where a salesperson can find and prioritise accounts (share the link).
2. A Git repository with source code and a short write-up: approach, key decisions, and how you measured whether it works.
