package main

import (
	"log"
	"os"
	"sync"
	"time"
)

func main() {
	var wg sync.WaitGroup
	configPath := "config.toml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}
	CONFIG, err := ReadConfig(configPath)
	if err != nil {
		log.Fatal(err)
	}
	listeners := make(map[string]*UDPListener)

	defer func() {
		for _, l := range listeners {
			l.Stop()
		}
	}()

	WriteConfigToRedis(CONFIG)
	for _, endpoint := range CONFIG.Endpoint {
		listener, err := NewUDPListener(endpoint.LocalPort, endpoint.RemoteAddress, endpoint.RemotePort, &wg, endpoint.WireGuard)
		if err != nil {
			log.Printf("Failed to Create listener due to error %t", err)
			continue
		}
		err = listener.Start()
		if err != nil {
			log.Printf("Failed to start listener due to erro %t", err)
			continue
		}
		listeners[endpoint.Name] = &listener
	}
	go ConfigUpdateLoop(CONFIG, listeners, &wg)
	wg.Wait()
}

func ConfigUpdateLoop(config Config, listeners map[string]*UDPListener, wg *sync.WaitGroup) {
	for {
		ReadConfigFromRedis(config.Redis.Address, config.Redis.Port, config.Redis.DB, config.Redis.Password, config.Redis.Prefix, listeners, wg)
		log.Println(listeners)
		time.Sleep(time.Duration(config.Redis.Update) * time.Second)
	}
}
