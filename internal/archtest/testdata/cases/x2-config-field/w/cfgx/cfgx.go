package cfgx

type Leaked struct {
	Held  string `json:"-"`
	Plain string
}
