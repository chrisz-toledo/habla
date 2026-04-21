package main

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

func main() {
fmt.Println("=== INICIANDO ESCANEO EN GO ===")
objetivo := "scanme.nmap.org"
resultado := func() map[string]interface{} {
    var wg sync.WaitGroup
    var mu sync.Mutex
    openPorts := []int{}
    closedPorts := []int{}
    ports := []int{80, 443, 22, 3306, 8080}
    
    for _, p := range ports {
        wg.Add(1)
        go func(port int) {
            defer wg.Done()
            address := objetivo + ":" + strconv.Itoa(port)
            conn, err := net.DialTimeout("tcp", address, 2*time.Second)
            
            mu.Lock()
            defer mu.Unlock()
            if err == nil {
                conn.Close()
                openPorts = append(openPorts, port)
            } else {
                closedPorts = append(closedPorts, port)
            }
        }(p)
    }
    wg.Wait()
    
    return map[string]interface{}{
        "target": objetivo,
        "open_ports": openPorts,
        "closed_ports": closedPorts,
        "method": "goroutines (stdlib)",
    }
}()
fmt.Println(resultado)
}
