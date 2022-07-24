package model

import (
	"sync"
	"time"
)

type VulnCache struct {
	cache map[string][]Vulnerability
}

var vulnCache VulnCache
var cacheMutex sync.Mutex

// supposed to be called concurrently with `go`
func StartCache() {
	vulnCache = VulnCache{
		cache: make(map[string][]Vulnerability),
	}
	for {
		cleanup()
	}
}

func cleanup() {
	// wait for 12 hours before cleaning up the cache
	time.Sleep(12 * time.Hour)
	cacheMutex.Lock()
	vulnCache = VulnCache{
		cache: make(map[string][]Vulnerability),
	}
	cacheMutex.Unlock()
}

func CacheVuln(key string, vulns []Vulnerability) {
	cacheMutex.Lock()
	vulnCache.cache[key] = vulns
	cacheMutex.Unlock()
}

func GetCachedVuln(key string) []Vulnerability {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()
	return vulnCache.cache[key]
}
