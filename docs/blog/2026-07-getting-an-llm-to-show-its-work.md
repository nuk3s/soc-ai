# Getting an LLM to show its work

*July 2026*

During an eval run a few days ago, my own software refused to do what I built it to do. It was right.

soc-ai has one optional cloud path: the Oracle, a second opinion on hard alerts. It's off by default, and when you do turn it on, everything that leaves is sanitized first — internal hostnames, usernames, and IPs replaced before the prompt goes anywhere. Behind the sanitizer sits a second, dumber check: an egress gate whose only job is to look at the sanitizer's *output* and refuse to send it if anything internal-looking survived. Fail closed. No retry with fingers crossed. Just stop.

Mid-eval, the gate stopped. It had found a hostname in a supposedly clean prompt: a DNS-SD service record, one of those underscore-led mDNS names shaped like `_aaplcache._tcp.<your-suffix>` (an Apple content-cache advertisement). My redaction regex had a mental picture of what a hostname looks like, and labels starting with underscores weren't in it. That form had walked past redaction at every layer.

So far, the system working as designed — a fail-closed check catching a real leak class before it left the building. The uncomfortable part came when I dug into *why* the gate had seen it at all. The detector flagged the name by accident: a JSON-escaping quirk happened to make the string visible to it. A sibling form of the same name would have gone through silently. And the bug wasn't new. It had been there through every eval I'd run before that day. All of them passed.

The fix was not a cleverer regex; regexes are how I got into this. The fix was a property test: 640 generated combinations of leading labels, middle labels, suffixes, and surrounding context, pinning one invariant — **anything the detector flags, the replacer must already have caught**. The detector and the replacer are two separate pieces of code with two separate pictures of "hostname," and they can no longer drift apart without CI going red.

Two things I keep from that day. Fail-closed design saved me from my own regex. And "it passed the evals" is a claim about the evals, not about the system.

## The problem I'm actually solving

[soc-ai](https://github.com/nuk3s/soc-ai) is self-hosted LLM triage for Security Onion. It reads the alerts on your grid, pulls the related events and the host's recent history, runs the indicators through local threat intel, decodes packets off the sensor when the payload matters, and writes a verdict with a confidence number and the reasoning that got it there. The reasoning runs on a model *you* host, behind an OpenAI-compatible gateway. By default nothing about your network leaves it. Apache-2.0, no meter, no phone-home.

Alert triage is the one job in a SOC that LLMs are genuinely good at, and the one place you least want to ship data to someone else's cloud — because an alert queue is the most sensitive map of your network that exists: hostnames, usernames, internal IPs, which servers talk to which at 3 a.m. That tension is why this project exists.

But self-hosting only removes one trust problem. The other one is the model itself.

## An analyst you can't fully trust

Language models are confidently wrong in a way human junior analysts are not. A junior analyst who's guessing usually looks like they're guessing. A model that's guessing writes three paragraphs of assured, well-structured rationale citing events it never looked at. If that's going in front of a security team, "we prompt it to be careful" is not a control. A prompt is a request; a gate is a guarantee.

So most of what makes soc-ai worth using is deterministic code that sits outside the model and assumes it lies:

- **A verdict has to cite tool-call evidence, or a gate downgrades it.** If the model calls something a false positive but the investigation record holds no evidence behind that call, code — not another prompt — forces the verdict down to "needs more info" and logs why. The model doesn't get to say "trust me."

- **When the pipeline fails, the UI says so.** If the model errors out or produces something unusable mid-investigation, the result is labelled *pipeline fallback* — its own chip in the queue, filterable. It was tempting to call these "preliminary assessments." They're fallbacks. The label says fallback.

- **Unfit models get caught at the door.** `soc-ai doctor` probes the configured analyst model for actual fitness for this job — not "does it respond," but whether it can drive tools and produce a valid verdict at the context sizes triage needs. That check exists because I burned an afternoon on a model that chatted beautifully and could not emit a well-formed verdict to save its life. It would have produced garbage silently in production; instead it fails loudly at setup.

- **The gates themselves are regression-tested.** A golden harness replays realistic alerts through the real pipeline in CI using scripted model doubles — a fake model that plays its part from a script — and asserts not just the final verdict but *which gates fired*. If a refactor quietly disarms the evidence gate, the build fails.

- **The trust boundary is inspectable.** The console has an egress policy page, and redaction previews that show the original next to the sanitized version with every changed span highlighted. You don't have to take my word for what would leave your network; you can look at it, on your own data, before you enable anything.

## The features that aren't there

The strongest claims I can make about soc-ai are about things I measured and then refused to ship on.

Self-consistency voting — sample the verdict several times, take the majority — is a popular reliability trick, and I had it built and ready. Measured on 32 real alerts from my own queue: zero split votes. Not one disagreement for the vote to resolve. What it did reliably produce was 18% more latency. It ships off (`verdict_consistency_samples = 1`), and the A/B writeup lives in the repo.

A starter pack of generic SOC runbooks — beaconing, brute force, DNS tunneling, the classics — measured as zero effect on verdicts. No verdict flips across paired alerts; agreement moved from 0.89 to 0.90, which is noise. Generic knowledge doesn't move a model that already knows what beaconing is. Your knowledge is different: which hosts are known-benign, how your team actually tunes each rule class. So the product now distills your own investigation history into org-specific draft runbooks — once a rule has a few completed investigations behind it, you get a one-click draft grounded in what actually happened on your network.

And investigation memory — letting the agent see prior verdicts on similar alerts — sounds obviously useful, and is also exactly the shape of anchoring bias: yesterday's "false positive" whispering in today's ear. It ships off. I have an A/B running right now to measure the anchoring effect before it earns a default.

The pattern behind all three: every feature that defaults on is something an operator has to trust without having chosen it. I measure first.

## What it runs on

My lab runs soc-ai against DeepSeek-V4-Flash with a 1M-token context window, served from a two-node NVIDIA DGX Spark (GB10) cluster behind LiteLLM. Two years ago that sentence would have been science fiction for a home lab, and it's the part of this story I find most hopeful: capable open-weight models on hardware you own are no longer exotic, which is what makes "zero egress by default" a real design decision rather than a compliance checkbox.

Nothing in soc-ai assumes my hardware, though. It talks to whatever your OpenAI-compatible gateway serves, lets you pick from the gateway's live model list at setup, and the doctor tells you honestly whether the model you picked is up to the job.

The rest is the unglamorous kind of engineering: 2,466 tests at 84% coverage, a Playwright end-to-end run against a seeded demo in CI, a nightly micro-eval that tracks verdict quality over time and alarms on regressions, WAL-safe backups you can take while it runs, and a console that has grown to about thirty screens. A setup script walks you through install and checks your connections before it builds anything, so a wrong password fails in seconds rather than after a build. I re-ran the whole install from a bare Rocky Linux box this week, pretending to be an analyst with twenty minutes of patience: clone to healthy container in under a minute once Docker was on.

## Try it

If you run Security Onion and can serve a model, you can point this at your own queue today:

```bash
git clone https://github.com/nuk3s/soc-ai.git && cd soc-ai
./setup.sh --prebuilt
```

Repo: [github.com/nuk3s/soc-ai](https://github.com/nuk3s/soc-ai) · Docs: [nuk3s.github.io/soc-ai](https://nuk3s.github.io/soc-ai/)

If the egress gate ever refuses you, go look at why. Mine was right.

It's free, it's Apache-2.0, and it's yours.
