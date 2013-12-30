package main

import (
	"code.google.com/p/go9p/p"
	"code.google.com/p/go9p/p/srv"
	/*"crypto/tls"
	"crypto/x509"*/
	"io/ioutil"
	"flag"
	"fmt"
	"log"
	"os"
	"io"
	"time"
	"strings"
	"syscall"
)

/* Append only */
type Chat struct {
	srv.File
	file *os.File
	path string
}
/* A folder where chats can be created */
type Chans struct {
	srv.File
}
/* One line file, truncate forced
Writable by op only */
type Status struct {
	srv.File
	file *os.File
}

// FIXME check the rsa key instead of the ip
func isop(fid *srv.FFid) bool {
	return strings.Contains(fid.Fid.Fconn.Id, "127.0.0.1")
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

func (f *Chans) Create(fid *srv.FFid, name string, perm uint32) (*srv.File, error) {
	chat := new(Chat)
	err := chat.Add(&chans.File, name, user, nil, perm, chat)
	chat.path = string(append([]byte("chans/"), chat.Name...))
	createifnotexist(chat.file, chat.path)

	return &chat.File, err
}

func (f *Chat) Wstat(fid *srv.FFid, dir *p.Dir) error {
	var uid, gid uint32

	f.Lock()
	defer f.Unlock()

	up := s.Upool
	uid = dir.Uidnum
	gid = dir.Gidnum
	if uid == p.NOUID && dir.Uid != "" {
		user := up.Uname2User(dir.Uid)
		if user == nil {
			return srv.Enouser
		}

		f.Uidnum = uint32(user.Id())
	}

	if gid == p.NOUID && dir.Gid != "" {
		group := up.Gname2Group(dir.Gid)
		if group == nil {
			return srv.Enouser
		}

		f.Gidnum = uint32(group.Id())
	}

	if dir.Mode != 0xFFFFFFFF {
		f.Mode = (f.Mode &^ 0777) | (dir.Mode & 0777)
	}

	if dir.Name != "" {
		if err := f.Rename(dir.Name); err != nil {
			return err
		}
	}

	if dir.Length != 0xFFFFFFFFFFFFFFFF {
		e := os.Truncate(f.path, int64(dir.Length))
		if e != nil {
			return e
		}
	}

	// If either mtime or atime need to be changed, then
	// we must change both.
	if dir.Mtime != ^uint32(0) || dir.Atime != ^uint32(0) {
		mt, at := time.Unix(int64(dir.Mtime), 0), time.Unix(int64(dir.Atime), 0)
		if cmt, cat := (dir.Mtime == ^uint32(0)), (dir.Atime == ^uint32(0)); cmt || cat {
			st, e := os.Stat(f.path)
			if e != nil {
				log.Println(fmt.Sprintf("Error: %s", e))
				return nil
			}
			switch cmt {
			case true:
				mt = st.ModTime()
			default:
				stat := st.Sys().(*syscall.Stat_t)
				at = time.Unix(stat.Atim.Unix())
			}
		}
		e := os.Chtimes(f.path, at, mt)
		if e != nil {
			log.Println(fmt.Sprintf("Error: %s", e))
			return nil
		}
	}

	return nil
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
	case p.OEXEC:
		uflag = os.O_RDONLY
		break
	}

	if mode&p.OTRUNC != 0 {
		uflag |= os.O_TRUNC
	}

	var err error
	f.file, err = os.OpenFile(f.path, uflag, 0666)
	return err
}

func (f *Chat) Read(fid *srv.FFid, buf []byte, offset uint64) (int, error) {

	count, e := f.file.ReadAt(buf, int64(offset))
	if e != nil && e != io.EOF {
		log.Println(fmt.Sprintf("Error: %s", e))
	}

	return count, nil
}

func dir2Qid(d os.FileInfo) *p.Qid {
	var qid p.Qid

	qid.Path = d.Sys().(*syscall.Stat_t).Ino
	qid.Version = uint32(d.ModTime().UnixNano() / 1000000)
	qid.Type = dir2QidType(d)

	return &qid
}

func dir2QidType(d os.FileInfo) uint8 {
	ret := uint8(0)
	if d.IsDir() {
		ret |= p.QTDIR
	}

	if d.Mode()&os.ModeSymlink != 0 {
		ret |= p.QTSYMLINK
	}

	return ret
}

func atime(stat *syscall.Stat_t) time.Time {
	return time.Unix(stat.Atim.Unix())
}

func dir2Npmode(d os.FileInfo, dotu bool) uint32 {
	ret := uint32(d.Mode() & 0777)
	if d.IsDir() {
		ret |= p.DMDIR
	}

	return ret
}

func (f *Chat) Stat(fid *srv.FFid) (error) {

	st, e := os.Lstat(f.path)
	if e != nil {
		log.Println(fmt.Sprintf("Error: %s", e))
	}

	sysMode := st.Sys().(*syscall.Stat_t)

	f.Qid = *dir2Qid(st)
	f.Mode = dir2Npmode(st, true)
	f.Atime = uint32(atime(sysMode).Unix())
	f.Mtime = uint32(st.ModTime().Unix())
	f.Length = uint64(st.Size())

	return nil
}

func (f *Chat) Write(fid *srv.FFid, buf []byte, offset uint64) (int, error) {

	/*ind := []byte(time.Now().Format(time.RFC3339))
	ind = append(ind, " "...)
	ind = append(ind, fid.Fid.Fconn.Id...)
	ind = append(ind, " → "...)

	n1, e1 := f.file.WriteAt(ind, int64(offset))
	if e1 != nil {
		log.Println(fmt.Sprintf("Error: %s", e1))
	}*/

	//n2, e2 := f.file.WriteAt(buf, int64(offset) + int64(n1))
	n2, e2 := f.file.WriteAt(buf, int64(offset))
	if e2 != nil {
		log.Println(fmt.Sprintf("Error: %s", e2))
	}

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

	var err error
	f.file, err = os.OpenFile(f.Name, uflag, 0666)
	return err
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

var addr = flag.String("addr", ":5640", "network address")
var debug = flag.Bool("d", false, "print debug messages")
var debugall = flag.Bool("D", false, "print packets as well as debug messages")

var Enotyours = &p.Error{"not yours", p.EPERM}
var s *srv.Fsrv
var root = new(srv.File)
var user = p.OsUsers.Uid2User(os.Geteuid())
var chans = new(Chans)

func main() {
	var err error

	flag.Parse()

	// root directory
	err = root.Add(nil, "/", user, nil, p.DMDIR|0655, root)
	if err != nil {
		log.Println(fmt.Sprintf("Error: %s", err))
		return
	}

	// chans directory
	err = chans.Add(root, "chans", user, nil, p.DMDIR|0655, chans)
	if err != nil {
		log.Println(fmt.Sprintf("Error: %s", err))
		return
	}
	if _, err := os.Stat("chans"); os.IsNotExist(err) {
		err = os.Mkdir("chans", os.ModeDir|0777)
		if err != nil {
			log.Println(fmt.Sprintf("Error: %s", err))
			return
		}
	}
	files, _ := ioutil.ReadDir("chans")
	for _, file := range files {
		chat := new(Chat)
		err := chat.Add(&chans.File, file.Name(), user, nil, 0666, chat)
		if err != nil {
			log.Println(fmt.Sprintf("Error: %s", err))
			return
		}
		chat.path = string(append([]byte("chans/"), chat.Name...))
		createifnotexist(chat.file, chat.path)
	}

	// public chat file
	public := new(Chat)
	err = public.Add(root, "public", user, nil, 0666, public)
	if err != nil {
		log.Println(fmt.Sprintf("Error: %s", err))
		return
	}
	public.path = public.Name
	createifnotexist(public.file, public.path)

	// private chat file
	private := new(Chat)
	err = private.Add(root, "private", user, nil, 0222, private)
	if err != nil {
		log.Println(fmt.Sprintf("Error: %s", err))
		return
	}
	private.path = private.Name
	createifnotexist(private.file, private.path)

	// status file
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
	pem, err := ioutil.ReadFile("ca.crt.pem")
	success := certpool.AppendCertsFromPEM(pem)

	if ! success {
		log.Println("can't parse cert pool")
		return
	}

	cert, err := tls.LoadX509KeyPair("server.crt.pem", "server.key.pem")
	if err != nil {
		log.Println(fmt.Sprintf("Error: %s", err))
		return
	}

	ls, oerr := tls.Listen("tcp", *addr, &tls.Config{
		//Rand:               rand.Reader,
		Certificates:       []tls.Certificate{cert},
		//CipherSuites:       []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA},
		CipherSuites:       []uint16{tls.TLS_RSA_WITH_AES_256_CBC_SHA},
		//ClientAuth:         tls.RequireAndVerifyClientCert,
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
