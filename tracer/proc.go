package tracer

import (
	"fmt"
	"io/ioutil"
)

// clearRefs clears the ru_maxrss counter (/proc/[pid]/clear_refs 5 to clear maxrss)
func clearRefs(pid int) error {
	return ioutil.WriteFile(fmt.Sprintf("/proc/%d/clear_refs", pid), []byte("5"), 0755)
}
