package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"strconv"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/go-redis/redis/v7"
)

type endpoint struct {
	Name          string
	WireGuard     bool
	RemoteAddress string
	RemotePort    int
	LocalPort     int
}

type redisConfig struct {
	Port     int
	DB       int
	Address  string
	Password string
	Prefix   string
	Update   int
}

type Config struct {
	Redis    redisConfig
	Endpoint []endpoint
}

func ReadConfig(path string) (Config, error) {
	confBin, err := ioutil.ReadFile(path)
	var config Config
	if err != nil {
		return config, err
	}
	confStr := string(confBin)
	_, err = toml.Decode(confStr, &config)
	if err != nil {
		return config, err
	}
	return config, nil
}

func WriteConfigToRedis(config Config) error {
	client := redis.NewClient(&redis.Options{
		Addr:     config.Redis.Address + ":" + strconv.Itoa(config.Redis.Port),
		Password: config.Redis.Password,
		DB:       config.Redis.DB,
	})
	defer client.Close()

	for _, endpt := range config.Endpoint {
		endptBytes, err := json.Marshal(endpt)
		if err != nil {
			return err
		}
		err = client.Set(config.Redis.Prefix+endpt.Name, endptBytes, 0).Err()
		if err != nil {
			return err
		}
	}
	return nil
}

func ReadConfigFromRedis(addr string, port int, db int, password string, prefix string, listeners map[string]*UDPListener, wg *sync.WaitGroup) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr + ":" + strconv.Itoa(port),
		Password: password,
		DB:       db,
	})
	defer client.Close()

	configKeys := client.Keys(prefix + "*")

	// Update Listeners with Configuration from Redis
	for _, key := range configKeys.Val() {
		if prefix != "" {
			spl := strings.Split(key, prefix)
			if len(spl) > 1 {
				key = spl[1]
			} else {
				continue
			}
		}
		configJsonStr := client.Get(key)
		if configJsonStr == nil {
			continue
		}
		log.Printf("config %s", configJsonStr)
		_, ok := listeners[key]
		if !ok {
			// Add new Listeners
			configString, err := client.Get(prefix + key).Result()
			if err != nil {
				continue
			}
			endpt := endpoint{}
			err = json.Unmarshal([]byte(configString), &endpt)
			if err != nil {
				continue
			}
			listener, err := NewUDPListener(endpt.LocalPort, endpt.RemoteAddress, endpt.RemotePort, wg, endpt.WireGuard)
			if err != nil {
				continue
			}
			err = listener.Start()
			if err != nil {
				log.Printf("Failed to start listener due to erro %t", err)
				continue
			}
			listeners[key] = &listener
		} else {
			// TODO Update Old Listeners
			configString, err := client.Get(key).Result()
			if err != nil {
				continue
			}
			endpt := endpoint{}
			err = json.Unmarshal([]byte(configString), &endpt)
			if err != nil {
				continue
			}

		}
	}

	// Remove Listeners that are not stored in redis
	for key, l := range listeners {
		FOUND := false
		for _, name := range configKeys.Val() {
			if prefix != "" {
				spl := strings.Split(key, prefix)
				if len(spl) > 1 {
					key = spl[1]
				} else {
					continue
				}
			}
			if name == key {
				FOUND = true
				break
			}
		}
		if FOUND {
			l.Stop()
			delete(listeners, key)
		}
	}
}
