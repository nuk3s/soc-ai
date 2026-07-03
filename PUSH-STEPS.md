# Push 1.0.3 then 1.0.4 to GitHub — in sequence

This repo (`/tmp/soc-ai-gh`) is a clone of GitHub `nuk3s/soc-ai` (base = **1.0.2**,
`054735c`) with two release commits stacked on top, each verified CI-green
(ruff check + ruff format --check + mypy + leak-gate) and leak-clean:

    054735c  1.0.2   (current GitHub HEAD)
    2e7b912  1.0.3   (tag v1.0.3)
    3a57045  1.0.4   (tag v1.0.4)   <- local main HEAD

`origin` = https://github.com/nuk3s/soc-ai.git (push uses YOUR credentials).

## Step 1 — publish 1.0.3, then verify GitHub Actions goes green

    cd /tmp/soc-ai-gh
    git push origin 2e7b912:main      # advances GitHub main to 1.0.3
    git push origin v1.0.3            # publishes the tag/release point

Watch the CI on the Actions tab. When it's green (and Pages, if you gate on it),
continue.

## Step 2 — publish 1.0.4

    cd /tmp/soc-ai-gh
    git push origin main             # local main is 1.0.4 -> fast-forwards GitHub main
    git push origin v1.0.4

## Notes
- Sequenced on purpose: main advances 1.0.2 → 1.0.3 → 1.0.4 with a stop in between.
- Nothing is force-pushed; both are normal fast-forward commits on GitHub's history.
- To abort after step 1, just don't run step 2 — GitHub stays at 1.0.3.
- Commits are authored as nuk3s <44327449+nuk3s@users.noreply.github.com>, matching
  prior releases.
