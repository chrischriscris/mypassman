# Project atlas

Open [index.html](index.html) in a browser. The folder works offline without
installing packages or starting a server. Keep its four runtime files together:
`index.html`, `styles.css`, `data.js`, and `app.js`.

The atlas is the visual entry point for the proposed rebuild. **Map** shows
every system; select one to read its chapter beside the map. **Decisions**
lists open questions first. **Walkthroughs** steps through intended sync
behavior. **Log** tracks delivery evidence and activity. The existing
implementation remains reference material. A walkthrough does not execute the
password manager or establish a security property.

## One record for each kind of information

- `../PRODUCT-BRIEF.md`: requirements and explicit product choices.
- `../ARCHITECTURE-PROPOSAL.md`: the current proposed design and boundaries.
- `data.js`: overview map, next steps, and foundation links; concise system
  index, delivery status, decision index, walkthroughs, implementation evidence,
  and activity. Entries link to the supporting record.
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

## Extending the atlas

Add another chapter or scenario to `data.js` using the existing shape. Place
each new system once in `overview.map`; the checker rejects a map that omits or
repeats one. Link directly with `#map/<system>`, `#decisions/<decision>`, or
`#walkthroughs/<scenario>/<step>`. Keep interactions in `app.js` and appearance
in `styles.css`.

The visual vocabulary carries meaning. Tinted regions are trusted: keys and
plaintext may exist inside them. Everything outside holds only ciphertext and
access metadata. Status rings fill as commitment grows: dashed for open or not
started, outlined for proposed or in progress, half-filled for implemented, and
filled for chosen or verified. Do not reuse these as decoration.

Add a separate detailed demonstration only when a chapter needs it, linking
back to its system and the design record. Avoid a build pipeline, backend, or
additional framework until a concrete need justifies it.
