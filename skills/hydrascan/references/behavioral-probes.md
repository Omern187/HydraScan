# Probes for state, exports and real execution paths

Read for apps with imports/exports, asynchronous state, persistence, background jobs, multiple startup paths or native bridges. Select probes from architecture and the consequences of failure. These patterns came from reviews where existing tests passed but omitted failure ordering, malformed data, alternate launchers and generated artifacts. They are not a requirement to inject every failure into every app.

## Write the oracle before the test

Record the supported trigger, invariant and a legitimate control. Observe the UI/result, in-memory or cached state, durable state and state after reload/restart where relevant. A displayed success, thrown exception or passing test is only one observation.

For an injected failure, distinguish the dependency failure you intentionally caused from the application's incorrect response to it. Use the actual storage/transaction code where feasible and fail one boundary deliberately. A mock that manufactures the alleged result cannot validate it.

## Choose the probes that matter

| Boundary | Small meaningful probe | Invariant and evidence |
| --- | --- | --- |
| Startup and distribution variants | Open each relevant supported launcher or release asset copy; verify module/dependency loading, then complete a small core journey | A served HTML page or HTTP 200 is not successful initialization. Record missing imports/exports and asset-map differences. Distinguish source assets, locally built output and committed binaries; do not infer that a binary contains the reviewed source. |
| Out-of-order asynchronous reads | Start input A, delay its real read, select B and let B finish, then release A; inspect the final export or committed state | Follow the product's selection/cancellation rule. For a last-selection-wins importer, an old completion must not overwrite newer state. Check every asynchronous loader; a generation guard on one importer does not protect another. |
| Export serialization | Import a valid small dataset through the UI and independently read each relevant downloaded format, including formulas and stored results | Accepted columns, values and types survive every serializer. In JavaScript object-keyed outputs, try permitted special keys such as __proto__ or constructor; establish the actual consequence before claiming prototype pollution or code execution. |
| Validation versus final consumer | Pass a boundary value accepted by the app to the real workbook/file/protocol library through the supported journey | Validation must agree with the final consumer's constraints. A successful validator alone does not prove a downloadable artifact can be generated; include a legitimate control. |
| Error visibility and completion | Trigger a bounded real operation failure and observe status after catch/finally, refresh callbacks and promise settlement | Failure remains visible and no false ready/success replaces it. Verify whether a file, write or external effect actually happened; UI text alone is insufficient. |
| Malformed request and service recovery | On a disposable local service, send a small malformed encoding or shape after a healthy request, then repeat the healthy request | Invalid input produces a controlled response without terminating the service. Observe process exit and subsequent reachability. Record source binding separately from tested network exposure; loopback reproduction does not establish remote reachability. |
| Streamed text decoding | Send the same small valid Unicode document in one piece and in bounded chunks splitting a multibyte character; include a byte-limit boundary when relevant | Chunk boundaries must not change accepted keys, values or request-size decisions. Observe actual HTTP chunks and final data; independently decoding each Buffer can corrupt characters. Measure limits against incoming bytes, not re-encoded replacement text. |
| Keyed authorization or dispatch | Trace externally supplied credentials/roles/action names into object or map lookup; compare a valid key, an unknown key and relevant inherited-property names | A truthy inherited property is not an issued identity or registered handler. Prove access to a protected effect through the actual route before claiming authentication bypass; safe Map/own-property lookups are counterevidence. |
| Identifier transport | Create/import a supported identifier containing a delimiter or Unicode, then read and export it through the public API using normal encoding | Accepted identifiers remain addressable. Compare decoding before route matching with per-segment decoding; do not count an explicitly prohibited identifier as a defect. |
| Shared-file commit concurrency | Run a small pair of legitimate overlapping writes, including different users/workspaces when they share one file; inspect responses, durable state and restart | Accepted writes remain present, temporary paths do not collide, and rejected operations do not silently commit changes. Atomic rename alone does not serialize a read-modify-write transaction or make a shared temporary filename safe. |
| Multi-step persistence | Seed an identifiable old record, attempt a new record, fail a later write once; include plain/compressed paths when present | Failure preserves the old committed state or explicitly reports partial completion. Read durable data independently, including the key that failed; inspect cache as well as metadata/markers. |
| Save lifecycle | Delay a real asynchronous save, attempt supported navigation/reload, then read persisted data after the delay or restart | Unsaved changes remain protected until commit, or the app completes the save before exiting. A cleared queue flag is not completion; account for writes and locks still in flight. |
| Backup/document import | Begin with valid data; change one field consumed by rendering or a later job to an invalid shape; import through the normal UI | The entire input is validated before replacement. Rejection preserves old data. A successful import must render and survive reload, not merely pass a parser or type assertion. |
| Cross-record relationships | Use one duplicate ID, missing parent, invalid active selection or mismatched workspace where applicable | Records remain uniquely addressable and relationships valid. Establish the actual expected rule before calling a collision a bug. |
| Equivalent feature paths | Compare manual/automatic/background/closed-window export, alternate importer or privileged path using the same synthetic records | The same product rule applies across paths. Compare meaningful normalized fields; ignore expected timestamp/selection differences. Trace every serializer or bypass of shared validation. |
| Native/web boundary | Follow an imported or edited value from the renderer through the actual bridge handler to the final file/URL operation | Input validation happens at the authority boundary. Observe the resolved path, file type, protocol and required user interaction. A mock records forwarding; only real authorized native execution establishes the final OS effect. |
| Recovery after failure | Reload after a rejected import, restart after a write failure, or retry after partial work | The app can open, retains committed data, communicates unsaved work and avoids duplicate effects. An error boundary alone is not recovery if persisted corruption causes the next startup to fail. |
| Resource/time limits | Trace where size/depth/decompression limits act relative to allocation and parsing; use a small bounded sample only if useful | Limits are enforced before costly work. A timer on the same thread cannot interrupt synchronous work; missing cancellation does not alone prove an exploitable hang. Keep impact unverified until supported. |

For durable-state comparisons, keep synthetic old/new markers small in the evidence even if the payload is large. Do not fill a real disk, kill a user's application, execute an untrusted file or flood a live service to prove these invariants.

## Make the fixture faithful

- Confirm the button, route or job is reachable with the chosen supported role and configuration before adding timing or hostile input. If the normal product hides an entrypoint in that state, investigate a different reachable path or discard the hypothesis.
- Prefer an actual-app check for integration claims. A component harness can establish a component/hook defect, but cannot prove all surrounding navigation, authorization or native behavior.
- Seed disposable accounts/data only as needed. A reload fixture must not overwrite the state being tested on every page load. Preserve the same storage instance when testing restart persistence.
- Keep unrelated dependencies valid. For example, a native bridge mock should provide harmless backup-directory behavior if startup uses it; setup errors from missing mock methods are not findings.
- Bound waits and release delays or close isolated contexts in cleanup. Record whether a probe completed, failed setup, never reached its trigger or produced inconclusive evidence. Do not count a timeout as a product bug without tracing its cause.
- Use real parsers and application callbacks whenever feasible. If you replace file existence or an OS opener with mocks, report exactly those substitutions; never claim that a process launched, a scheduled task ran or a native window behaved as tested by a browser mock.

## Record and close the claim

A compact probe record is sufficient:

```text
Revision/build and runtime surface
Supported entrypoint/role; synthetic fixture and legitimate control
Expected invariant and source of that expectation
Injected delay/failure, if any; real versus mocked dependencies
Completion status; actual UI/cache/durable/reloaded observations
Proof state, actual consequence, remaining native/live gaps
Evidence and cleanup; bug-demonstration versus intended-behavior assertion
```

A reachable trace can support `source-confirmed`; component/browser observation can support `dynamic-confirmed` for that tested consequence. Do not promote a mocked native result into observed OS behavior. Preserve a disproved candidate in the checkpoint with the reason it was rejected, so later reviews do not rediscover it as a confirmed finding.

When a calculation accepts an optional scope such as date window, tenant, units or selected subset, trace whether the real caller supplies it. Compare scoped and unscoped synthetic results. A difference is only a candidate until the intended business rule is established; do not silently choose a rule for the user.
