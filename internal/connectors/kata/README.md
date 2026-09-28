# kata — the reference DRIVER (型, `kind: kata`)

**THE FORM A DRIVER AUTHOR REPEATS (D176, D244).** In memory, no transport, and complete in every
contract a driver can implement: the efferent `Driver`, a `Source` (poll, recovery, D241) and a
`Drifter` (the `kata_surface` setting, D311), a `Refiner` (`reflexes.yaml`: a receipt of each read
and write, D317 — the rule that puts a seiren beside a `CommandResult`), and a `Presetter` and
`Leveled` (`presets.yaml`: `kata.viewer` and `kata.contributor` over fictional levels viewer <
contributor < owner, and no owner preset on purpose, D327), and a suggested `anzen.yaml` ceiling
(its one irreversible write, D337). Its tests run all five published suites —
`conformance.Run`, `RunSource`, `RunDrift`, `RunRefiner` and `RunPresetter` — and deliberately NOT `RunHTTP`, because it has no
statuses to classify (D167).

It is also the acceptance run's fixture, which is why so many steps import it.

**`hako/` IS THE BOX AND THIS IS WHAT IS IN IT** (D244): `hako/reference/kata.yaml` is the
governance half that turns this driver into a connector, and `hako/BLUEPRINT.md` is the teaching
text. `internal/connectorcheck` holds this folder to the connector shape (D316).
