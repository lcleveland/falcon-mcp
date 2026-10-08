package falcon

//go:generate go run ./gen

// Op is one Falcon API operation, keyed by its FalconPy operation ID.
type Op struct {
	Method string
	Path   string // may hold {name} parameters
	Scope  string // the API scope the call needs, e.g. "Hosts:read"
	// Write marks an operation that changes tenant state. Writes are never
	// retried; Falcon has POST reads, so this is not inferred from Method.
	Write bool
}

// Lookup finds an operation by ID.
func Lookup(id string) (Op, bool) {
	op, ok := ops[id]
	return op, ok
}
