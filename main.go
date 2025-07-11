package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"strings"
	"syscall"
	"time"

	"github.com/chzyer/readline"
	"github.com/spf13/pflag"
	"github.com/theckman/yacspin"
	"golang.org/x/term"
)

const (
	AUTH_REQUEST       byte = 1
	COMMAND_REQUEST    byte = 2
	RESPONSE           byte = 3
	AUTH_RESPONSE      byte = 4
	MAX_MESSAGE_SIZE        = 8192
	MAX_COMMAND_LENGTH      = 256
)

type Client struct {
	host     string
	port     int
	conn     net.Conn
	username string
}

var (
	host     = pflag.StringP("host", "h", "localhost", "Server hostname")
	port     = pflag.IntP("port", "p", 33737, "Server port")
	password = pflag.StringP("password", "P", "", "Admin password")
	command  = pflag.StringP("command", "c", "", "Execute single command and exit")
	userFlag = pflag.StringP("user", "u", "", "Username to display in logs")
	timeout  = pflag.IntP("timeout", "t", 10, "Connection timeout in seconds")
	version  = pflag.BoolP("version", "v", false, "Show version")
	help     = pflag.Bool("help", false, "Show help")
)

func main() {
	pflag.Parse()

	if *help {
		showUsage()
		return
	}

	if *version {
		fmt.Println("rei v1.0 - Minecraft Remote Admin")
		return
	}

	fmt.Println("rei - Minecraft Remote Admin")

	initSpinner, _ := yacspin.New(yacspin.Config{
		Frequency:       100 * time.Millisecond,
		CharSet:         yacspin.CharSets[36],
		Suffix:          " Starting up",
		SuffixAutoColon: true,
		Message:         "rei",
		StopMessage:     "Ready!",
		StopCharacter:   "[+]",
		StopColors:      []string{"fgGreen"},
	})
	initSpinner.Start()
	time.Sleep(300 * time.Millisecond)
	initSpinner.Stop()

	if *userFlag == "" {
		currentUser, err := user.Current()
		if err != nil {
			fmt.Println("Error: Could not detect current user")
			fmt.Println("Use -u flag to specify username manually")
			fmt.Println("Example: ./rei -u platon -P mypassword")
			os.Exit(1)
		}
		*userFlag = currentUser.Username
	}

	client := &Client{
		host: *host,
		port: *port,
	}

	if !client.connect() {
		os.Exit(1)
	}
	defer client.conn.Close()

	if !client.authenticate() {
		os.Exit(1)
	}

	if *command != "" {
		client.executeCommand(*command)
		return
	}

	client.startCommandLoop()
}

func showUsage() {
	currentUser, err := user.Current()
	username := "<username>"
	if err == nil && currentUser.Username != "" {
		username = currentUser.Username
	}
	fmt.Println("rei - Minecraft Remote Admin Client")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  rei [options]")
	fmt.Printf("  rei -h server.example.com -p 33737 -P mypassword -u %s\n", username)
	fmt.Printf("  rei -c \"list\" -P mypassword -u %s\n", username)
	fmt.Println()
	fmt.Println("Options:")
	pflag.PrintDefaults()
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Printf("  rei -u %s                    # Connect to localhost:33737\n", username)
	fmt.Printf("  rei -h mc.server.com -u %s    # Connect to remote server\n", username)
	fmt.Printf("  rei -c \"say Hello\" -P pass123 -u %s # Execute single command\n", username)
}

func (c *Client) connect() bool {
	spinner, _ := yacspin.New(yacspin.Config{
		Frequency:       120 * time.Millisecond,
		CharSet:         yacspin.CharSets[26],
		Suffix:          fmt.Sprintf(" Connecting to %s:%d", c.host, c.port),
		SuffixAutoColon: true,
		Message:         "TCP",
		StopMessage:     "Connected!",
		StopCharacter:   "->",
		StopColors:      []string{"fgGreen"},
	})
	spinner.Start()

	done := make(chan bool, 1)
	var conn net.Conn
	var err error

	go func() {
		conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", c.host, c.port))
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(time.Duration(*timeout) * time.Second):
		spinner.StopFailMessage("Connection timeout")
		spinner.StopFail()
		fmt.Printf("Error: Connection timeout after %d seconds\n", *timeout)
		fmt.Println("\nTroubleshooting:")
		fmt.Println("- Check if the server is running")
		fmt.Println("- Check if the rei plugin is loaded (/plugins)")
		fmt.Println("- Check if port 33737 is open")
		fmt.Println("- Look for 'Rei RCON server started' in server logs")
		fmt.Println("- Try with -t 30 for longer timeout")
		return false
	}

	if err != nil {
		spinner.StopFailMessage("Connection failed")
		spinner.StopFail()
		fmt.Printf("Error: %v\n", err)
		fmt.Println("\nTroubleshooting:")
		fmt.Println("- Check if the server is running")
		fmt.Println("- Check if the rei plugin is loaded (/plugins)")
		fmt.Println("- Check if port 33737 is open")
		fmt.Println("- Look for 'Rei RCON server started' in server logs")
		return false
	}

	c.conn = conn
	spinner.Stop()
	return true
}

func (c *Client) authenticate() bool {
	var pass string

	if *password != "" {
		pass = *password
	} else {
		fmt.Print("Password: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Printf("\nPassword read error: %v\n", err)
			return false
		}
		fmt.Println()

		if len(passwordBytes) == 0 {
			fmt.Println("Password cannot be empty")
			return false
		}
		pass = string(passwordBytes)
	}

	authData := pass + ":" + *userFlag

	authSpinner, _ := yacspin.New(yacspin.Config{
		Frequency:       150 * time.Millisecond,
		CharSet:         yacspin.CharSets[35],
		Suffix:          " Authenticating",
		SuffixAutoColon: true,
		Message:         "Auth",
		StopMessage:     "Authenticated!",
		StopCharacter:   "[OK]",
		StopColors:      []string{"fgGreen"},
	})
	authSpinner.Start()

	err := c.sendMessage(AUTH_REQUEST, authData)
	if err != nil {
		authSpinner.StopFailMessage("Auth request failed")
		authSpinner.StopFail()
		fmt.Printf("Error: %v\n", err)
		return false
	}

	msgType, response, err := c.readMessage()
	if err != nil {
		authSpinner.StopFailMessage("Auth response failed")
		authSpinner.StopFail()
		fmt.Printf("Error: %v\n", err)
		return false
	}

	if msgType == AUTH_RESPONSE && strings.HasPrefix(response, "SUCCESS:") {
		c.username = strings.TrimPrefix(response, "SUCCESS:")
		authSpinner.Stop()
		return true
	}

	authSpinner.StopFailMessage("Authentication failed")
	authSpinner.StopFail()
	fmt.Printf("Reason: %s\n", strings.TrimPrefix(response, "FAILED:"))
	return false
}

func (c *Client) startCommandLoop() {
	fmt.Println("\nReady to execute commands!")
	fmt.Println("Type 'help' for available commands, 'exit' to quit")
	fmt.Println()

	rl, err := readline.NewEx(&readline.Config{
		Prompt:      c.getPrompt(),
		HistoryFile: "/tmp/rei_history",
	})
	if err != nil {
		panic(err)
	}
	defer rl.Close()

	for {
		line, err := rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				if len(line) == 0 {
					break
				} else {
					continue
				}
			} else if err == io.EOF {
				break
			}
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if line == "exit" || line == "quit" {
			fmt.Println("Goodbye!")
			break
		}

		if line == "help" {
			c.showHelp()
			continue
		}

		c.executeCommand(line)
	}
}

func (c *Client) getPrompt() string {
	return fmt.Sprintf("rei@%s> ", c.username)
}

func (c *Client) executeCommand(command string) {
	if len(command) > MAX_COMMAND_LENGTH {
		fmt.Printf("Command too long (max %d characters)\n", MAX_COMMAND_LENGTH)
		return
	}

	spinner, _ := yacspin.New(yacspin.Config{
		Frequency:       80 * time.Millisecond,
		CharSet:         yacspin.CharSets[9],
		Suffix:          " processing",
		SuffixAutoColon: true,
		Message:         command,
	})
	spinner.Start()

	err := c.sendMessage(COMMAND_REQUEST, command)
	if err != nil {
		spinner.StopFailMessage("send failed")
		spinner.StopFail()
		fmt.Printf("Error: %v\n", err)
		return
	}

	_, response, err := c.readMessage()
	spinner.Stop()

	if err != nil {
		fmt.Printf("Response error: %v\n", err)
		return
	}

	c.handleResponse(response)
}

func (c *Client) handleResponse(response string) {
	if strings.HasPrefix(response, "SUCCESS:") {
		content := strings.TrimPrefix(response, "SUCCESS:")
		if strings.Contains(content, "\n") {
			fmt.Printf("[OK]\n%s\n", content)
		} else {
			fmt.Printf("[OK] %s\n", content)
		}
	} else if strings.HasPrefix(response, "FAILED:") {
		content := strings.TrimPrefix(response, "FAILED:")
		if strings.Contains(content, "\n") {
			fmt.Printf("[FAILED]\n%s\n", content)
		} else {
			fmt.Printf("[FAILED] %s\n", content)
		}
	} else if strings.HasPrefix(response, "ERROR:") {
		fmt.Printf("[ERROR] %s\n", strings.TrimPrefix(response, "ERROR:"))
	} else {
		fmt.Printf("%s\n", response)
	}
}

func (c *Client) sendMessage(msgType byte, data string) error {
	message := []byte(data)
	length := int32(len(message) + 1)

	if err := binary.Write(c.conn, binary.BigEndian, length); err != nil {
		return err
	}
	if err := binary.Write(c.conn, binary.BigEndian, msgType); err != nil {
		return err
	}
	_, err := c.conn.Write(message)
	return err
}

func (c *Client) readMessage() (byte, string, error) {
	var length int32
	if err := binary.Read(c.conn, binary.BigEndian, &length); err != nil {
		return 0, "", err
	}

	if length > MAX_MESSAGE_SIZE || length < 1 {
		return 0, "", fmt.Errorf("invalid message size: %d", length)
	}

	var msgType byte
	if err := binary.Read(c.conn, binary.BigEndian, &msgType); err != nil {
		return 0, "", err
	}

	data := make([]byte, length-1)
	if _, err := io.ReadFull(c.conn, data); err != nil {
		return 0, "", err
	}

	return msgType, string(data), nil
}

func (c *Client) showHelp() {
	fmt.Println("Commands:")
	fmt.Println("  help     - Show this help message")
	fmt.Println("  exit     - Disconnect and exit")
	fmt.Println("  <cmd>    - Execute any Minecraft server command")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  list")
	fmt.Println("  tp player1 player2")
	fmt.Println("  give player diamond 64")
	fmt.Println("  ban player reason")
	fmt.Println("  say Hello from remote admin!")
}
