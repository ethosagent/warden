package policy

import "time"

// SetNowForTest swaps the evaluator clock. Test-only (this file is compiled
// into the policy tests, never into the product).
func (e *Evaluator) SetNowForTest(f func() time.Time) { e.now = f }
