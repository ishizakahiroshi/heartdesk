// Package filelock retains the application's internal import path. OS locking
// and its contention sentinel are owned by the public shared package.
package filelock

import publiclock "github.com/ishizakahiroshi/heartpost/filelock"

var ErrLocked = publiclock.ErrLocked

func Acquire(path string) (func(), error)    { return publiclock.Acquire(path) }
func TryAcquire(path string) (func(), error) { return publiclock.TryAcquire(path) }
