package utils

import (
	"fmt"
	"net"
)

// GetFreePort asks the OS for a free open port between 9000-9999
func GetFreePort() (int, error) {
	for port := 9000; port < 10000; port++ {
		addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("localhost:%d", port))
		if err != nil {
			continue
		}

		l, err := net.ListenTCP("tcp", addr)
		if err != nil {
			continue
		}
		l.Close()
		return port, nil
	}

	return 0, fmt.Errorf("no free port available in range 9000-9999")
}