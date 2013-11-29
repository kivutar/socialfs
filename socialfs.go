package main

import (
	"code.google.com/p/go9p/p"
	"code.google.com/p/go9p/p/srv"
	/*"crypto/tls"
	"crypto/x509"
	"io/ioutil"*/
	"flag"
	"fmt"
	"log"
	"os"
)

type Chat struct {
	srv.File
	data [][]byte
}

var addr = flag.String("addr", "localhost:5640", "network address")
var debug = flag.Bool("d", false, "print debug messages")
var debugall = flag.Bool("D", false, "print packets as well as debug messages")

var blkchan = make(chan []byte, 2048)

var s *srv.Fsrv

func (f *Chat) Read(fid *srv.FFid, buf []byte, offset uint64) (int, error) {
	f.Lock()
	defer f.Unlock()

	if offset > f.Length {
		return 0, nil
	}

	count := uint32(len(buf))
	if offset+uint64(count) > f.Length {
		count = uint32(f.Length - offset)
	}

	for n, off, b := offset/uint64(8192), offset%uint64(8192), buf[0:count]; len(b) > 0; n++ {
		m := 8192 - int(off)
		if m > len(b) {
			m = len(b)
		}

		blk := make([]byte, 8192)
		if len(f.data[n]) != 0 {
			blk = f.data[n]
		}

		copy(b, blk[off:off+uint64(m)])
		b = b[m:]
		off = 0
	}

	return int(count), nil
}

func (f *Chat) Write(fid *srv.FFid, buf []byte, offset uint64) (int, error) {
	f.Lock()
	defer f.Unlock()

	sz := offset + uint64(len(buf))
	if f.Length < sz {
		f.expand(sz)
	}

	count := 0
	for n, off := offset/uint64(8192), offset%uint64(8192); len(buf) > 0; n++ {
		log.Println(n)
		blk := f.data[n]
		if len(blk) == 0 {

			select {
			case blk = <-blkchan:
				break
			default:
				blk = make([]byte, 8192)
			}

			copy(blk, make([]byte, 8192))

			f.data[n] = blk
		}

		m := copy(blk[off:], buf)
		buf = buf[m:]
		count += m
		off = 0
	}

	return count, nil
}

func (f *Chat) expand(sz uint64) {
	blknum := sz / uint64(8192)
	if sz%uint64(8192) != 0 {
		blknum++
	}

	data := make([][]byte, blknum)
	if f.data != nil {
		copy(data, f.data)
	}

	f.data = data
	f.Length = sz
}

func main() {
	var err error

	flag.Parse()
	user := p.OsUsers.Uid2User(os.Geteuid())
	root := new(srv.File)
	err = root.Add(nil, "/", user, nil, p.DMDIR|0555, nil)
	if err != nil {
		log.Println(fmt.Sprintf("Error: %s", err))
		return
	}

	public := new(Chat)
	err = public.Add(root, "public", p.OsUsers.Uid2User(os.Geteuid()), nil, 0666, public)
	if err != nil {
		log.Println(fmt.Sprintf("Error: %s", err))
		return
	}

	s = srv.NewFileSrv(root)
	s.Dotu = true

	if *debug {
		s.Debuglevel = 1
	}
	if *debugall {
		s.Debuglevel = 2
	}

	/*certpool := x509.NewCertPool()
	pem, err := ioutil.ReadFile("/home/kivutar/client3.cert")
	success := certpool.AppendCertsFromPEM(pem)

	if ! success {
		log.Println("can't parse cert pool")
		return
	}

	cert, err := tls.LoadX509KeyPair("/home/kivutar/server2.cert", "/home/kivutar/server2.privkey")
	if err != nil {
		log.Println(fmt.Sprintf("Error: %s", err))
		return
	}

	ls, oerr := tls.Listen("tcp", *addr, &tls.Config{
		//Rand:               rand.Reader,
		Certificates:       []tls.Certificate{cert},
		//CipherSuites:       []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA},
		//ClientAuth:         tls.RequireAndVerifyClientCert,
		//ClientCAs:          certpool,
		InsecureSkipVerify: true,
		//PreferServerCipherSuites: true,
	})
	if oerr != nil {
		log.Println("can't listen:", oerr)
		return
	}

	err = s.StartListener(ls)*/

	s.Start(s)
	err = s.StartNetListener("tcp", *addr)
	if err != nil {
		log.Println(fmt.Sprintf("Error: %s", err))
		return
	}

	return
}
