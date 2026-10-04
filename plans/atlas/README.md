# Project atlas

Open [index.html](index.html) in a browser. The folder works offline without
installing packages or starting a server. Keep its four runtime files together:
`index.html`, `styles.css`, `data.js`, and `app.js`.

The atlas is the visual entry point for the proposed rebuild. It contains a
system map, chapters, open decisions, conceptual walkthroughs, and evidence.
The existing implementation remains reference material. A walkthrough does
not execute the password manager or establish a security property.

## One record for each kind of information

- `../PRODUCT-BRIEF.md`: requirements and explicit product choices.
- `../ARCHITECTURE-PROPOSAL.md`: the current proposed design and boundaries.
- `data.js`: concise system index, delivery status, decision index, walkthroughs,
  implementation evidence, and activity. Entries link to the supporting record.
- `../LEGACY-REFERENCE.md`: access to archived code and legacy specifications.
  Establish new normative specifications alongside approved replacement formats
  and protocols; legacy specifications are not the rebuild contract.

Do not maintain a second full architecture document inside the page. Update
the relevant source and its short atlas entry together. Archived `DESIGN.html`
and `docs/sync-explainer.html` describe earlier work; see the legacy reference
for access. Main is the fresh implementation starting point.

## Working system by system

1. Open the chapter and explain the intended behavior and failure cases.
2. Record the decision, reason, alternatives, and affected systems in the
   relevant design record. Update the decision index only after an explicit
   maintainer choice; an assistant recommendation stays proposed.
3. Scope a small change and state the meaningful completion check. Mark the
   corresponding delivery status in progress only when work actually starts.
4. Add links to the implementation when it exists. Record known gaps in the
   chapter rather than hiding them behind a completion percentage.
5. Attach verification evidence: command or procedure, result, date, exact
   code revision/snapshot, and limits. A new change that invalidates the result
   returns the affected system to implemented or in progress until rechecked.
6. Update the diagram/walkthrough if behavior changed. Add a short activity
   entry in the same change. Run `node plans/atlas/check.mjs` from the repo root.

`design` and `implementation` are separate. Choosing Rust does not mean a new
core exists. The delivery states are `not-started`, `in-progress`, `implemented`,
and `verified`. `implemented` requires linked code evidence; `verified` also
requires a `verification` object with `command`, `result`, `date`, `revision`,
and `limits`. Store longer reports in files and link them from `evidence`.
The checker validates these records and local links; it does not run or verify
the claimed product tests.

## Decision drafts

The page can save a preference and note in browser storage. These drafts do
not modify files, authorize implementation, or change the recorded decision.
Use **Export drafts** to download JSON and provide it for review. After the
maintainer decides, record the accepted choice and rationale in the project,
then refresh the atlas entry. No server or external service receives drafts.

Storage is tied to the browser and page location. If storage is unavailable,
the page reports that drafts are temporary; export before closing. Keep
repository decisions in version control rather than relying on browser state.

## Extending the atlas

Add another chapter or scenario to `data.js` using the existing shape. Keep
interactions in `app.js` and appearance in `styles.css`. Add a separate detailed
demonstration only when the chapter needs it, linking back to its system and
the design record. Avoid a build pipeline, backend, or additional framework
until a concrete need justifies it.
