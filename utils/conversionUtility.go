package utility

import (
	"strconv"
	"time"
)

// convert the string to int64
func StringToInt64(s string) int64 {
	var i int64
	i, _ = strconv.ParseInt(s, 10, 64)
	return i
}

// convert string to time.duration
func StringToDuration(s string) (d time.Duration, err error) {
	d, err = time.ParseDuration(s)
	return
}
