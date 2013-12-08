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
	"time"
	"strings"
)

/* Append only */
type Chat struct {
	srv.File
	file *os.File
}
/* One line file, truncate forced
Writable by op only */
type Status struct {
	srv.File
	file *os.File
}

var addr = flag.String("addr", ":5640", "network address")
var debug = flag.Bool("d", false, "print debug messages")
var debugall = flag.Bool("D", false, "print packets as well as debug messages")

var Enotyours = &p.Error{"not yours", p.EPERM}

var s *srv.Fsrv

// FIXME check the rsa key instead of the ip
func isop(fid *srv.FFid) bool {
	return strings.Contains(fid.Fid.Fconn.Id, "127.0.0.2")
}

func createifnotexist(file *os.File, path string) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		file, err = os.OpenFile(path, os.O_CREATE, 0666)
		if err != nil {
			log.Println(fmt.Sprintf("Error: %s", err))
			return
		}
	}
}

func (f *Chat) Open(fid *srv.FFid, mode uint8) (error) {

	uflag := int(0)
	switch mode & 3 {
	case p.OREAD:
		uflag = os.O_RDONLY
		break
	case p.ORDWR:
		uflag = os.O_RDWR
		break
	case p.OWRITE:
		uflag = os.O_WRONLY
		break
	}

	var e
	f.file, e = os.OpenFile(f.Name, uflag, 0666)
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

	ind := []byte(time.Now().Format(time.RFC3339))
	ind = append(ind, " "...)
	ind = append(ind, fid.Fid.Fconn.Id...)
	ind = append(ind, " → "...)

	n1, e1 := f.file.WriteAt(ind, int64(offset))
	if e1 != nil {
		log.Println(fmt.Sprintf("Error: %s", e1))
	}

	n2, e2 := f.file.WriteAt(buf, int64(offset) + int64(n1))
	if e2 != nil {
		log.Println(fmt.Sprintf("Error: %s", e2))
	}

	st, e := os.Lstat(f.Name)
	if e != nil {
		log.Println(fmt.Sprintf("Error: %s", e))
	}
	f.Length = uint64(st.Size())
	f.Mtime = uint32(st.ModTime().Unix())

	return n2, nil
}

func (f *Status) Open(fid *srv.FFid, mode uint8) (error) {

	uflag := int(0)
	switch mode & 3 {
	case p.OREAD:
		uflag = os.O_RDONLY
		break
	case p.OWRITE:
		uflag = os.O_WRONLY | os.O_TRUNC
		break
	}

	var e
	f.file, e = os.OpenFile(f.Name, uflag, 0666)
	return e
}

func (f *Status) Read(fid *srv.FFid, buf []byte, offset uint64) (int, error) {

	count, e := f.file.ReadAt(buf, int64(offset))
	if e != nil && e != io.EOF {
		log.Println(fmt.Sprintf("Error: %s", e))
	}

	return int(count), nil
}

func (f *Status) Write(fid *srv.FFid, buf []byte, offset uint64) (int, error) {

	if ! isop(fid) {
		return len(buf), Enotyours // FIXME
	}

	n, e2 := f.file.WriteAt(buf, int64(offset))
	if e2 != nil {
		log.Println(fmt.Sprintf("Error: %s", e2))
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
	createifnotexist(public.file, public.Name)

	private := new(Chat)
	err = private.Add(root, "private", user, nil, 0222, private)
	if err != nil {
		log.Println(fmt.Sprintf("Error: %s", err))
		return
	}
	createifnotexist(private.file, private.Name)

	status := new(Status)
	err = status.Add(root, "status", user, nil, 0666, status)
	if err != nil {
		log.Println(fmt.Sprintf("Error: %s", err))
		return
	}
	createifnotexist(status.file, status.Name)

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
