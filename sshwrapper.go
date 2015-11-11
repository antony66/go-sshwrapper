package sshwrapper

import (
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type SSHConn struct {
	client *ssh.Client
}

func NewSSHConn(user, host string, port int, socket string) (*SSHConn, error) {
	agentConn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, err
	}
	defer agentConn.Close()
	sshAgent := agent.NewClient(agentConn)
	signers, err := sshAgent.Signers()
	if err != nil {
		return nil, err
	}
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signers...)},
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, err
	}
	return &SSHConn{client}, nil
}

func (s *SSHConn) Close() {
	s.client.Close()
}

func (s *SSHConn) Output(cmd string, in io.Reader) ([]byte, error) {
	session, err := s.client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	session.Stdin = in
	return session.Output(cmd)
}

func (s *SSHConn) CombinedOutput(cmd string, in io.Reader) ([]byte, error) {
	session, err := s.client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	session.Stdin = in
	return session.CombinedOutput(cmd)
}

func (s *SSHConn) Run(cmd string, in io.Reader, outWriter, errWriter io.Writer) error {
	session, err := s.client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	session.Stdout = outWriter
	session.Stderr = errWriter
	session.Stdin = in
	err = session.Run(cmd)
	return err
}
