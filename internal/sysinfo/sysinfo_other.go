//go:build !windows

package sysinfo

import "time"

// Build no está disponible fuera de Windows.
func Build() string { return "" }

// InstallDate no está disponible fuera de Windows.
func InstallDate() (time.Time, bool) { return time.Time{}, false }
