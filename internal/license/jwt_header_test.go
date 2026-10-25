package license

// The negative JWT fixtures can construct malformed headers without retaining
// an application-side implementation of the shared token codec.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}
