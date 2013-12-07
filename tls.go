// Connects to a server over TLS and lists the specified directory
package main

import (
	"code.google.com/p/go9p/p"
	"code.google.com/p/go9p/p/clnt"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"flag"
	"fmt"
	"log"
	"os"
)

var debuglevel = flag.Int("d", 0, "debuglevel")
var addr = flag.String("addr", "localhost:5640", "network address")

func main() {
	var user p.User
	var file *clnt.File

	flag.Parse()
	user = p.OsUsers.Uid2User(os.Geteuid())
	clnt.DefaultDebuglevel = *debuglevel

	certpool := x509.NewCertPool()
	pem, err := ioutil.ReadFile("server.crt")
	success := certpool.AppendCertsFromPEM(pem)
	if ! success {
		log.Println("can't parse cert pool")
		return
	}

	cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
	if err != nil {
		log.Println(fmt.Sprintf("Error: %s", err))
		return
	}

	c, oerr := tls.Dial("tcp", *addr, &tls.Config{
		ServerName:         "localhost",
		Rand:               rand.Reader,
		Certificates:       []tls.Certificate{cert},
		CipherSuites:       []uint16{tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA},
		RootCAs:            certpool,
		InsecureSkipVerify: false,
	})
	if oerr != nil {
		log.Println("can't dial", oerr)
		return
	}

	clnt, err := clnt.MountConn(c, "", user)
	if err != nil {
		goto error
	}

	if flag.NArg() != 1 {
		log.Println("invalid arguments")
		return
	}

	file, oerr = clnt.FOpen(flag.Arg(0), p.OREAD)
	if oerr != nil {
		goto oerror
	}

	for {
		d, oerr := file.Readdir(0)
		if oerr != nil {
			goto oerror
		}

		if d == nil || len(d) == 0 {
			break
		}

		for i := 0; i < len(d); i++ {
			os.Stdout.WriteString(d[i].Name + "\n")
		}
	}

	file.Close()
	return

error:
	log.Println(fmt.Sprintf("Error: %s", err))
	return

oerror:
	log.Println("Error", oerr)
}
