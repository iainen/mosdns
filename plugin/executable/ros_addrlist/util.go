package ros_addrlist

import (
	"strconv"
	"time"
)

func parseRosTimeout(t string) time.Duration {
	d := time.Duration(0)
	if len(t) == 0 {
		return d
	}
	num := ""
	for _, r := range t {
		v := string(r)
		if r < '0' || r > '9' {
			value, _ := strconv.Atoi(num)
			switch v {
			case "w":
				d += time.Duration(value) * time.Hour * 24 * 7
			case "d":
				d += time.Duration(value) * time.Hour * 24
			case "h":
				d += time.Duration(value) * time.Hour
			case "m":
				d += time.Duration(value) * time.Minute
			case "s":
				d += time.Duration(value) * time.Second
			}
			num = ""
		} else {
			num += v
		}
	}
	return d
}
