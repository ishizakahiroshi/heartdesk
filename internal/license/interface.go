package license

import publiclicense "github.com/ishizakahiroshi/heartpost/agentlicense"

type Verifier = publiclicense.Verifier

// New preserves the application's import path and linker configuration while
// giving each verifier an immutable copy of its signing material.
func New() Verifier { return newVerifier() }
