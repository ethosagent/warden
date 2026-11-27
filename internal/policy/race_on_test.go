//go:build race

package policy

// raceEnabled skips wall-clock timing checks under the race detector.
const raceEnabled = true
