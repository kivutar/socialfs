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
	"io"
)

type Chat struct {
	srv.File
	file *os.File
}

var addr = flag.String("addr", ":5640", "network address")
var debug = flag.Bool("d", false, "print debug messages")
var debugall = flag.Bool("D", false, "print packets as well as debug messages")

var s *srv.Fsrv

func omode2uflags(mode uint8) int {
	ret := int(0)
	switch mode & 3 {
	case p.OREAD:
		ret = os.O_RDONLY
		break

	case p.ORDWR:
		ret = os.O_RDWR
		break

	case p.OWRITE:
		ret = os.O_WRONLY
		break

	case p.OEXEC:
		ret = os.O_RDONLY
		break
	}

	if mode&p.OTRUNC != 0 {
		ret |= os.O_TRUNC
	}

	return ret
}

func (f *Chat) Open(fid *srv.FFid, mode uint8) (error) {

	var e error

	f.file, e = os.OpenFile(f.Name, omode2uflags(mode)|os.O_CREATE, 0666)

	return e
}

func (f *Chat) Read(fid *srv.FFid, buf []byte, offset uint64) (int, error) {

	count, e := f.file.ReadAt(buf, int64(offset))
	if e != nil && e != io.EOF {
		log.Println(fmt.Sprintf("Error: %s", e))
	}

	return int(count), nil
}

func (f *Chat) Write(fid *srv.FFid, buf []byte, offset uint64) (int, error) {

	n, e := f.file.WriteAt(buf, int64(offset))
	if e != nil {
		log.Println(fmt.Sprintf("Error: %s", e))
	}

	st, e := os.Lstat(f.Name)
	if e != nil {
		log.Println(fmt.Sprintf("Error: %s", e))
	}
	f.Length = uint64(st.Size())
	f.Mtime = uint32(st.ModTime().Unix())

	return n, nil
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
	err = public.Add(root, "public", user, nil, 0666, public)
	if err != nil {
		log.Println(fmt.Sprintf("Error: %s", err))
		return
	}

	private := new(Chat)
	err = private.Add(root, "private", user, nil, 0222, private)
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
	pem, err := ioutil.ReadFile("client.crt")
	success := certpool.AppendCertsFromPEM(pem)

	if ! success {
		log.Println("can't parse cert pool")
		return
	}

	cert, err := tls.LoadX509KeyPair("test.crt.pem", "test.key.pem")
	if err != nil {
		log.Println(fmt.Sprintf("Error: %s", err))
		return
	}

	ls, oerr := tls.Listen("tcp", *addr, &tls.Config{
		//Rand:               rand.Reader,
		Certificates:       []tls.Certificate{cert},
		CipherSuites:       []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA},
		ClientAuth:         tls.RequireAndVerifyClientCert,
		ClientCAs:          certpool,
		InsecureSkipVerify: false,
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
