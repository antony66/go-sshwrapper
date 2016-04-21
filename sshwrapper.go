package sshwrapper

import (
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type SSHConn struct {
	client       *ssh.Client
	agentConn    net.Conn
	forwardAgent bool
	envs         map[string]string
}

func NewSSHConn(user, host string, port int, socket string, forwardAgent bool) (*SSHConn, error) {
	agentConn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, err
	}
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

	if forwardAgent {
		if err := agent.ForwardToAgent(client, sshAgent); err != nil {
			return nil, fmt.Errorf("SetupForwardKeyring: %v", err)
		}
	}

	c := SSHConn{
		client:       client,
		agentConn:    agentConn,
		forwardAgent: forwardAgent,
	}
	return &c, nil
}

func (s *SSHConn) Close() {
	s.agentConn.Close()
	s.client.Close()
}

func (s *SSHConn) requestAgentForwarding(session *ssh.Session) error {
	if !s.forwardAgent {
		return nil
	}
	if err := agent.RequestAgentForwarding(session); err != nil {
		return fmt.Errorf("RequestAgentForwarding: %v", err)
	}
	return nil
}

func (s *SSHConn) Output(cmd string, in io.Reader) ([]byte, error) {
	session, err := s.client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	if err := s.requestAgentForwarding(session); err != nil {
		return nil, err
	}

	for k, v := range s.envs {
		if err := session.Setenv(k, v); err != nil {
			return nil, err
		}
	}

	session.Stdin = in

	return session.Output(cmd)
}

func (s *SSHConn) CombinedOutput(cmd string, in io.Reader) ([]byte, error) {
	session, err := s.client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	if err := s.requestAgentForwarding(session); err != nil {
		return nil, err
	}

	for k, v := range s.envs {
		if err := session.Setenv(k, v); err != nil {
			return nil, err
		}
	}

	session.Stdin = in

	return session.CombinedOutput(cmd)
}

func (s *SSHConn) Run(cmd string, in io.Reader, outWriter, errWriter io.Writer) error {
	session, err := s.client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	if err := s.requestAgentForwarding(session); err != nil {
		return err
	}

	for k, v := range s.envs {
		if err := session.Setenv(k, v); err != nil {
			return err
		}
	}

	session.Stdout = outWriter
	session.Stderr = errWriter
	session.Stdin = in
	err = session.Run(cmd)
	return err
}

func (s *SSHConn) SetEnvs(e map[string]string) {
	s.envs = e
}
