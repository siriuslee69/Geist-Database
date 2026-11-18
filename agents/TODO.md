# To do

What is still to do in this repo. Rules: Agent-Conventions/WORKFLOW.md, section 8.
An item that is done is removed here and named in PROGRESS.md.

- [ ] Teaching project: this repo has items in ../Vegvisir-TeachingPlan/plan/repos/Backbone.md (G1 to G5).
  why: the class room, room share and mail for teaching stand on them; their order across repos is kept in one place, not here.
  start: read ../Vegvisir-TeachingPlan/plan/STATUS.md, then the file above
  done when: that file holds no item for this repo.
  needs: nobody
  plan: ../Vegvisir-TeachingPlan/README.md, "How to use this repo": claim one item, do it here, close it there.

- [ ] boxlog.nim has 10 routines spread over 375 lines that `compactBox` calls as its steps (Otter: LAYOUT, 31 places in all).
  why: a reader has to jump through the file to follow one routine.
  start: ../Otter-RepoEvaluation/tools/agent_hooks/otter-gate.sh --force . | grep -A12 LAYOUT
  done when: Otter no longer lists boxlog.nim:74.
  needs: nobody
  plan: move the helpers of compactBox (logPath, sealBody, syncBox, newLogId, headerBytes, closeBoxFile, openBoxFile, copyFrame, liveSlots, removeOrphanBlobs) directly above it, one file per pass.
