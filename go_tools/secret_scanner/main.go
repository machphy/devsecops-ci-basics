package main

import (
    "bufio"
    "fmt"
    "os"
    "path/filepath"
    "regexp"
)

var secretPatterns = map[string]*regexp.Regexp{
    "AWS Access Key ID": regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
    "AWS Secret Access Key": regexp.MustCompile(`(?i)aws(.{0,20})?(secret|secret_access)_key(.{0,20})?=[ \t\"]?([A-Za-z0-9/+=]{40})`),
    "Generic API Key": regexp.MustCompile(`(?i)api[_-]?key[ \t\"]?[:=][ \t\"]?([A-Za-z0-9-_]{16,64})`),
    "JWT Token": regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
}

func main() {
    if len(os.Args) != 2 {
        fmt.Fprintln(os.Stderr, "Usage: go run . <file-to-scan>")
        os.Exit(1)
    }

    inputPath := os.Args[1]
    err := scanFile(inputPath)
    if err != nil {
        fmt.Fprintln(os.Stderr, "ERROR:", err)
        os.Exit(1)
    }
}

func scanFile(path string) error {
    file, err := os.Open(path)
    if err != nil {
        return err
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    lineNumber := 1
    found := false
    absolutePath, _ := filepath.Abs(path)

    for scanner.Scan() {
        line := scanner.Text()
        for name, pattern := range secretPatterns {
            if matches := pattern.FindStringSubmatch(line); len(matches) > 0 {
                found = true
                secretValue := matches[len(matches)-1]
                fmt.Printf("%s:%d %s -> %s\n", absolutePath, lineNumber, name, secretValue)
            }
        }
        lineNumber++
    }

    if err := scanner.Err(); err != nil {
        return err
    }

    if !found {
        fmt.Printf("No secrets detected in %s\n", absolutePath)
    }

    return nil
}
