package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"sync"
)

type UDPListener struct {
	WireGuard          bool
	LocalPort          int
	RemotePort         int
	RemoteAddress      string
	ServerConn         *net.UDPConn
	ClientConn         *net.UDPConn
	serverCloseChannel chan int
	clientCloseChannel chan int
	endAddr            *net.UDPAddr
	wg                 *sync.WaitGroup
}

func NewUDPListener(localPort int, remoteAddress string, remotePort int, wg *sync.WaitGroup, wireguard bool) (UDPListener, error) {
	listener := UDPListener{
		LocalPort:          localPort,
		RemotePort:         remotePort,
		RemoteAddress:      remoteAddress,
		wg:                 wg,
		WireGuard:          wireguard,
		serverCloseChannel: make(chan int),
		clientCloseChannel: make(chan int),
	}
	return listener, nil
}

func (listener *UDPListener) Start() error {
	listener.wg.Add(1)
	sAddr := fmt.Sprintf(":%d", listener.LocalPort)
	server, err := Udp4Server(sAddr)
	if err != nil {
		return err
	}
	listener.ServerConn = server
	cAddr := fmt.Sprintf("[%s]:%d", listener.RemoteAddress, listener.RemotePort)
	client, err := Udp6Client(cAddr)
	if err != nil {
		return err
	}
	listener.ClientConn = client
	go listener.ClientLoop()
	go listener.ServerLoop()
	return nil
}

func (l *UDPListener) Stop() {
	l.clientCloseChannel <- 1
	l.serverCloseChannel <- 1
	l.wg.Done()
}

func (l *UDPListener) ServerLoop() {
	buffer := make([]byte, 1500)
	for {
		select {
		case <-l.serverCloseChannel:
			l.ServerConn.Close()
			return
		default:
			n, addr, err := l.ServerConn.ReadFromUDP(buffer)
			if err != nil {
				log.Printf("Failed to receive in ServerLoop due to error %t", err)
				continue
			}
			if l.WireGuard {
				if (bytes.Compare(buffer[0:4], []byte{5, 0, 0, 0}) == -1) || (bytes.Compare(buffer[0:4], []byte{0, 0, 0, 0}) == 1) {
					l.endAddr = addr
					l.ClientConn.Write(buffer[:n])
				}
			} else {
				l.endAddr = addr
				l.ClientConn.Write(buffer[:n])
			}

		}
	}
}

func (l *UDPListener) ClientLoop() {
	buffer := make([]byte, 1500)
	for {
		select {
		case <-l.clientCloseChannel:
			l.ClientConn.Close()
			return
		default:
			n, _, err := l.ClientConn.ReadFromUDP(buffer)
			if err != nil {
				log.Printf("Failed to read in CleintLoop due to erro %t", err)
				continue
			}
			_, err = l.ServerConn.WriteToUDP(buffer[:n], l.endAddr)

		}
	}
}

func Udp6Client(addr string) (*net.UDPConn, error) {
	s, err := net.ResolveUDPAddr("udp6", addr)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	c, err := net.DialUDP("udp6", nil, s)
	if err != nil {
		fmt.Println(err)
		return c, err
	}
	return c, nil
}

func Udp4Server(addr string) (*net.UDPConn, error) {
	s, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, err
	}
	connection, err := net.ListenUDP("udp4", s)
	if err != nil {
		return nil, err
	}
	return connection, nil
}
