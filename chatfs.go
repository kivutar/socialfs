// Copyright 2009 The Go9p Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"code.google.com/p/go9p/p"
	"code.google.com/p/go9p/p/srv"
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

type In struct {
	srv.File
}

var addr = flag.String("addr", ":5640", "network address")
var debug = flag.Bool("d", false, "print debug messages")
var debugall = flag.Bool("D", false, "print packets as well as debug messages")

var chat = []byte{}

func (*In) Read(fid *srv.FFid, buf []byte, offset uint64) (int, error) {

	off := int(offset)

	for ;off > len(chat)-1; {
		time.Sleep(time.Second)
	}

	copy(buf, chat[off:])
	return len(chat) - off, nil
}

func (*In) Write(fid *srv.FFid, data []byte, offset uint64) (int, error) {
	addr := fid.Fid.Fconn.RemoteAddr().String()
	chat = append(chat, addr...)
	chat = append(chat, " > "...)
	chat = append(chat, data...)
        return len(data), nil
}

func main() {
	var err error
	var in *In
	var s *srv.Fsrv
	chat = append(chat, time.Now().String() + "\n"...)

	flag.Parse()
	user := p.OsUsers.Uid2User(os.Geteuid())
	root := new(srv.File)
	err = root.Add(nil, "/", user, nil, p.DMDIR|0555, nil)
	if err != nil {
		goto error
	}

	in = new(In)
	err = in.Add(root, "in", p.OsUsers.Uid2User(os.Geteuid()), nil, 0666, in)
	if err != nil {
		goto error
	}

	s = srv.NewFileSrv(root)
	s.Dotu = true

	if *debug {
		s.Debuglevel = 1
	}
	if *debugall {
		s.Debuglevel = 2
	}

	s.Start(s)
	err = s.StartNetListener("tcp", *addr)
	if err != nil {
		goto error
	}

	return

error:
	log.Println(fmt.Sprintf("Error: %s", err))
}
