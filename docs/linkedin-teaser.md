# LinkedIn teaser — "The Attack a Capability Boundary Can't Stop"
# Post this to LinkedIn; it drives traffic to the full article.
# Target: published after the website post goes live.

---

🔒 Sandboxing an AI agent stops it from reading `~/.ssh/id_rsa` and `curl`-ing it out.

But what about the data the agent read **legitimately** — internal notes, a design doc — then pasted into a PR body?

That's the attack a capability boundary **structurally cannot catch.** The read was in-scope. The boundary has no memory of what was read.

I built Capsule — a capability gateway for MCP tool calls — to close exactly that gap. Content-based taint tracks what the agent has seen and flags it when it shows up in an outbound channel, **even when the agent declares no provenance.** It survives base64/hex/chunked re-encoding (4/4 caught) and blocks the out-of-scope reads/exfil too.

The recording below isn't scripted: it's a real LLM (`gpt-4o-mini`) given a malicious README, getting prompt-injected, and getting contained at every turn — denied, sandboxed, or held for approval, three different responses to three different threats. ↓

Measured against an attack corpus with honeytokens at real secret paths:
• Secret reach: 5/5 unprotected → 0/5 with Capsule
• Tainted outbound caught: 6/6
• False denies: 0
• Legitimate tasks: still pass

Honest about what it *can't* stop (encryption, semantic paraphrase, steganography) — because a defense is only as trustworthy as its stated limits.

Full writeup — design, the two-attack insight, the threat model, and how to reproduce it:
🔗 https://www.senthilsiva.com/posts/the-attack-a-capability-boundary-cant-stop/

Code: github.com/senthil1216/mcp-capsule

#AI #Security #AIAgents #MCP #PromptInjection #AppSec #ZeroTrust
