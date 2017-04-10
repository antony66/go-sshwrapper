package sshwrapper

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// ConnTimeout specifies the maximum amount of time for the TCP connection to establish
var ConnTimeout = 60 * time.Second

// A SSHConn represents a connection to run remote commands.
type SSHConn struct {
	client       *ssh.Client
	agentConn    net.Conn
	forwardAgent bool
	envs         map[string]string
}

// Dial creates a client connection to the given SSH server.
//
// `addr` should be provided in the following format:
//
//     user@host:port
//
// if `forwardAgent` is true then forwarding of the authentication agent connection will be enabled.
func Dial(addr string, socket string, forwardAgent bool) (*SSHConn, error) {
	agentConn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, err
	}
	var agentOk bool
	defer func() {
		if !agentOk {
			agentConn.Close()
		}
	}()

	sshAgent := agent.NewClient(agentConn)
	signers, err := sshAgent.Signers()
	if err != nil {
		return nil, err
	}

	host, port, user, err := ParseAddr(addr)
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User:    user,
		Auth:    []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		Timeout: ConnTimeout,
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), config)
	if err != nil {
		return nil, err
	}
	var clientOk bool
	defer func() {
		if !clientOk {
			client.Close()
		}
	}()

	if forwardAgent {
		if err := agent.ForwardToAgent(client, sshAgent); err != nil {
			return nil, fmt.Errorf("SetupForwardKeyring: %v", err)
		}
	}

	agentOk = true
	clientOk = true

	c := SSHConn{
		client:       client,
		agentConn:    agentConn,
		forwardAgent: forwardAgent,
	}
	return &c, nil
}

// Close closes the connection
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

// Output runs cmd on the remote host and returns its standard output.
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

// CombinedOutput runs cmd on the remote host and returns its combined standard output and standard error.
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

// Run runs cmd on the remote host.
//
// See https://godoc.org/golang.org/x/crypto/ssh#Session.Run for details.
func (s *SSHConn) Run(cmd string, in io.Reader, outWriter, errWriter io.Writer) error {
	session, err := s.client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	if err = s.requestAgentForwarding(session); err != nil {
		return err
	}

	for k, v := range s.envs {
		if err = session.Setenv(k, v); err != nil {
			return err
		}
	}

	session.Stdout = outWriter
	session.Stderr = errWriter
	session.Stdin = in
	err = session.Run(cmd)
	return err
}

// SetEnvs specifies the environment that will be applied
// to any command executed by Output/CombinedOutput/Run.
func (s *SSHConn) SetEnvs(e map[string]string) {
	s.envs = e
}

// ParseAddr parses SSH connection string and if everything is correct
// returns three separate values -- host, port and user.
func ParseAddr(s string) (host string, port int, user string, err error) {
	port = 22
	user = "root"

	origAddr := s

	switch fields := strings.Split(s, "@"); {
	case len(fields) == 1:
	case len(fields) == 2:
		if len(fields[1]) == 0 {
			return "", 0, "", fmt.Errorf("incorrect addr format: %s", origAddr)
		}
		user, s = fields[0], fields[1]
	default:
		return "", 0, "", fmt.Errorf("incorrect addr format: %s", origAddr)
	}

	switch fields := strings.Split(s, ":"); {
	case len(fields) == 1:
		host = fields[0]
	case len(fields) == 2:
		if len(fields[1]) == 0 {
			return "", 0, "", fmt.Errorf("incorrect addr format: %s", origAddr)
		}
		host = fields[0]
		d, err := strconv.Atoi(fields[1])
		if err != nil {
			return "", 0, "", err
		}
		port = d
	default:
		return "", 0, "", fmt.Errorf("incorrect addr format: %s", origAddr)
	}

	return
}
