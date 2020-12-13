package cgroup

import "sync"

var (
	infoOnce  sync.Once
	cacheInfo map[string]int
)

func getCachedCgroupHierarchy() map[string]int {
	infoOnce.Do(func() {
		info, err := GetCgroupInfo()
		if err != nil {
			return
		}
		cacheInfo = make(map[string]int)
		for k, v := range info {
			if !v.Enabled {
				continue
			}
			cacheInfo[k] = v.Hierarchy
		}
	})
	return cacheInfo
}
