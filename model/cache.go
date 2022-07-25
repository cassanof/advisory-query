package model

import (
	"log"
	"sync"
	"time"
)

type VulnCache struct {
	cache map[string][]Vulnerability
}

var vulnCache VulnCache
var cacheMutex sync.Mutex

// supposed to be called concurrently with `go`
func StartTemporaryCache() {
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
	log.Println("Cleaning up cache... Cached vulnerabilities:", len(vulnCache.cache))
	cacheMutex.Lock()
	vulnCache = VulnCache{
		cache: make(map[string][]Vulnerability),
	}
	cacheMutex.Unlock()
}

func TempCacheVuln(key string, vulns []Vulnerability) {
	cacheMutex.Lock()
	vulnCache.cache[key] = vulns
	cacheMutex.Unlock()
}

func GetTempCachedVuln(key string) []Vulnerability {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()
	return vulnCache.cache[key]
}
