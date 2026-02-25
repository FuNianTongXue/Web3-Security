package ui

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Prompt struct {
	r *bufio.Reader
}

func NewPrompt() *Prompt {
	return &Prompt{r: bufio.NewReader(os.Stdin)}
}

func (p *Prompt) Ask(label string, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	line, _ := p.r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func (p *Prompt) Choose(label string, options []string) (int, error) {
	fmt.Println(label)
	for i, op := range options {
		fmt.Printf("  %d) %s\n", i+1, op)
	}
	fmt.Print("选择序号: ")
	line, _ := p.r.ReadString('\n')
	line = strings.TrimSpace(line)
	n, err := strconv.Atoi(line)
	if err != nil || n < 1 || n > len(options) {
		return -1, fmt.Errorf("无效选择")
	}
	return n - 1, nil
}
