package registryauth

// Mode defines how OwnDock authenticates to one OCI Registry connection.
// TLS transport trust is intentionally independent from authentication.
type Mode string

const (
	ModeAnonymous Mode = "anonymous"
	ModeBasic     Mode = "basic"
)

func (m Mode) Valid() bool {
	return m == ModeAnonymous || m == ModeBasic
}
