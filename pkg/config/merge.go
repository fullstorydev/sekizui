package config

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// part is one file's document, before composition.
type part struct {
	file string
	doc  *Document
}

// mergeClass is how one Document field composes across files (D278).
type mergeClass int

const (
	// entries: a list of independent entries, concatenated in file order.
	// Two files declaring the same entry is `Validate`'s refusal ("declared
	// twice"), which every entry list already has.
	entries mergeClass = iota + 1
	// keyed: a map, merged by key; a key declared in two files is refused.
	keyed
	// whole: one value that means something only as a whole — the stage
	// order, the jobs block — set in at most one file.
	whole
)

// mergeClasses classifies EVERY Document field. A field missing from here is
// refused by `TestEveryDocumentFieldHasAMergeClass`, so a new field cannot
// arrive with composition semantics nobody decided.
var mergeClasses = map[string]mergeClass{ //nolint:gochecknoglobals // immutable classification table, read-only after init
	"Stages": whole, "LLMStages": whole, "Jobs": whole, "CredentialPolicy": whole, "Version": whole,
	"Demo":    whole,
	"Targets": entries, "Grants": entries, "Reflexes": entries, "Refinements": entries, "Issuers": entries, "Sources": entries,
	"Anzen": entries, "Shin": entries, "Presets": entries, "ReflexBudgets": entries,
	"PayloadSchemas": keyed, "Policies": keyed, "MCPSpecs": keyed,
}

// merge composes parts into one Document with NO OVERRIDE (D278).
//
// **NOTHING A LATER FILE SAYS CAN REPLACE WHAT AN EARLIER ONE SAID.** Override
// semantics would make file ORDER a security property — a connector pack
// named `zz.yaml` redefining a payload schema the deployment reviewed — and
// the order is a filename. So a map key or a whole value declared twice is
// refused naming both files, and entry lists concatenate for `Validate` to
// refuse duplicates exactly as it does within one file.
//
// One part is returned as it came, so a single-file deployment is unchanged.
func merge(parts []part) (*Document, error) {
	if len(parts) == 1 {
		parts[0].doc.files = []string{parts[0].file}
		return parts[0].doc, nil
	}
	out := &Document{}
	ov := reflect.ValueOf(out).Elem()
	typ := ov.Type()
	declared := map[string]string{} // "field" or "field/key" -> file
	var problems []string
	for _, p := range parts {
		out.files = append(out.files, p.file)
		pv := reflect.ValueOf(p.doc).Elem()
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if !f.IsExported() {
				continue
			}
			src, dst := pv.Field(i), ov.Field(i)
			if src.IsZero() {
				continue
			}
			switch mergeClasses[f.Name] {
			case entries:
				dst.Set(reflect.AppendSlice(dst, src))
			case keyed:
				if dst.IsNil() {
					dst.Set(reflect.MakeMap(src.Type()))
				}
				iter := src.MapRange()
				for iter.Next() {
					k := fmt.Sprint(iter.Key().Interface())
					if first, dup := declared[f.Name+"/"+k]; dup {
						problems = append(problems, fmt.Sprintf("%s %q is declared in %s and again in %s",
							jsonName(f), k, first, p.file))
						continue
					}
					declared[f.Name+"/"+k] = p.file
					dst.SetMapIndex(iter.Key(), iter.Value())
				}
			case whole:
				if first, dup := declared[f.Name]; dup {
					problems = append(problems, fmt.Sprintf("%s is set in %s and again in %s; it is one "+
						"value, so exactly one file may set it", jsonName(f), first, p.file))
					continue
				}
				declared[f.Name] = p.file
				dst.Set(src)
			default:
				problems = append(problems, fmt.Sprintf("field %s has no merge class; this is a bug", f.Name))
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fmt.Errorf("%d composition conflict(s), and NOTHING overrides (D278):\n  - %s",
			len(problems), strings.Join(problems, "\n  - "))
	}
	return out, nil
}

func jsonName(f reflect.StructField) string {
	name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
	return name
}

// Files are the files this document was composed from, in merge order — for
// the boot log, so a hash on an audit row joins back to the files that made it.
func (d *Document) Files() []string { return d.files }
