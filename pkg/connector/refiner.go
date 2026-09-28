package connector

// Refiner is the OPTIONAL interface a driver implements when it ships
// `refines:` rules — its embedded `reflexes.yaml`, beside `schemas.yaml`
// (D299, D317).
//
// **OPTIONAL AND TYPE-ASSERTED (GO-PRIMER §2.2)**, as Source and Drifter are:
// D35 forbids adding a required method to Driver, and a connector with no rules
// to offer is not asked.
//
// **SHIPPED MEANS AVAILABLE, NOT IMPOSED.** The rules reach no caller until a
// deployment names one in `refinements:` (D297 ruling 2), so a driver release
// that adds a rule changes nothing any agent receives. The rules read the
// connector's own types and write seiren types its `Schemas()` declares — one
// type, one owner (D279) — in a vocabulary that is Sekizui's code, closed
// (D263, D300): the file chooses among operators, it cannot add one.
//
// The conformance suite's RunRefiner holds a Refiner to that: the file parses
// strictly, and every rule's types are the driver's own.
type Refiner interface {
	// Reflexes returns the raw `reflexes.yaml`, embedded in the binary.
	Reflexes() []byte
}
