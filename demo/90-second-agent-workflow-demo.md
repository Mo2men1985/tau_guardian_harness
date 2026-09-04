# 90-Second AI-Native Engineering Demo Script

## Goal

Show how I use coding agents for speed without allowing the implementation agent to certify its own work.

## Screen sequence + narration

**0-12 sec - The task**

Show a short issue/mission description and say:

> I start by converting the request into explicit acceptance criteria and a bounded change surface. The goal is to let the coding agent move fast without letting the definition of success drift during implementation.

**12-30 sec - Builder**

Show Claude Code working on the candidate and say:

> Claude Code is my implementation agent. It can inspect the repo, propose changes, write code and tests, and report what it changed. But its own report is not acceptance evidence.

**30-45 sec - Exact candidate**

Show the Git commit / PR head and say:

> Review is bound to an exact Git candidate. If the head changes, the previous review is stale. That prevents an approval from silently carrying over to different code.

**45-62 sec - Tests and negative controls**

Show test output or a mutation/negative test and say:

> I use ordinary tests plus negative or mutation controls where the risk justifies them. I want to see that the control fails when its protection is removed, not only that the happy-path test is green.

**62-78 sec - Independent verifier**

Show a Codex review or sanitized verifier report and say:

> A separate verifier reviews the exact candidate and the evidence. It can pass, abstain when evidence is insufficient, or veto when a blocking failure is reproduced. The builder does not grade itself.

**78-90 sec - Outcome**

Show the final decision/evidence summary and say:

> This is how I use AI as an engineering multiplier: fast implementation, explicit criteria, reproducible tests, independent review, and human ownership of consequential decisions. I am comfortable prototyping quickly, but I do not convert incomplete evidence into a production claim.

## Recording notes

- Keep the demo under 90 seconds.
- Use only sanitized screens; hide tokens, private URLs, customer data, and proprietary documents.
- Do not show giant evidence packs. Show one requirement, one implementation diff, one test, one verifier decision.
- If a live Codex/Claude session contains sensitive content, recreate the sequence in a disposable demo repository instead.
