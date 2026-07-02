package config

// AdvisoryConfig configures offline advisory mode.
type AdvisoryConfig struct {
	Enabled bool
}

type rawAdvisory struct {
	Enabled bool `yaml:"enabled"`
}
