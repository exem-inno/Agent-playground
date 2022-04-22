package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	coll, err := ebpf.LoadCollection("xdp.o")
	if err != nil {
		log.Fatal(err)
	}

	ifce, err := net.InterfaceByName("lo")
	if err != nil {
		log.Fatal(err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:	coll.Programs["xdp_drop"],
		Interface:	ifce.Index,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	<-sig
}
