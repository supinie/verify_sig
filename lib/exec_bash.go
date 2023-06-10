package lib

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
    "time"
    "strconv"
)

// Make_exec takes a filename as a string and changes the mode
// to allow it to be executed. This should only be run AFTER
// the signature has been verified.
func Make_exec(filename string) error {
    err := os.Chmod("./" + filename, 0555)
    return err
}

// Rm_file takes a filename as a string and deletes the file.
// This should be used to cleanup files recieved from clients
// after processing is complete and the connection is terminated.
func Rm_file(filename string) error {
    err := os.Remove("./" + filename)
    return err
}

// Exec_bash takes a filename as a string and executes the bash script given.
// It will return the output of the bash script as a string. This should
// only be run AFTER the signature has been verified.
func Exec_bash(filename string) (string, error) {
    out, err := exec.Command("./" + filename).Output()
    if err != nil {
        return "", err
    }
    return string(out), nil
}

// Write_to_file takes a bash script as a string slice (where every line is an element)
// and writes this to a file named after the client the script was recieved from, and
// the current epoc time. It returns the filename as a string, and creates the file in
// read only.
func Write_to_file(client string, script []string) (string, error) {
    filename := client + "_at_" + strconv.FormatInt(time.Now().Unix(), 10) // append time to ensure unique filename

    file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0444)
    if err != nil {
        fmt.Println(err)
        return "", err
    }
    writer := bufio.NewWriter(file)

    for _, data := range script {
        _, err = writer.WriteString(data + "\n")
        if err != nil {
            fmt.Println(err)
            return "", err
        }
    }

    writer.Flush()

    file.Close()
    return filename, err
}
