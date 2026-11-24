package sqlite

import "context"

// SetAfterRead installs a hook that runs after each registry load has read the
// database and before it is cached.
func SetAfterRead(s *Store, f func()) { s.afterRead = f }

// SetVersionReader replaces the data_version read Watch polls.
func SetVersionReader(s *Store, f func(context.Context) (int64, error)) { s.version = f }
