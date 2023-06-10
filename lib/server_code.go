package lib

import (
	"bufio"
	"fmt"
	"net"
    "encoding/hex"
    "os"
)

// Take_Connection handles each connection to enable concurrency of requests.
// It does not return anything, but will terminate the connection when the request
// has been fully processed, as well as giving similar (but not necesserily identical)
// output to StdOut.
func Take_Connection(connection net.Conn, verbose bool) {
    fmt.Printf("Serving %s\n", connection.RemoteAddr().String())

    var bash_script []string

    scanner := bufio.NewScanner(connection)

    for scanner.Scan() {
        if scanner.Text() == "===EOF===" {
            break
        }
        bash_script = append(bash_script, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        fmt.Println(err)
        connection.Write([]byte("Server error, closing connection.\n"))
        connection.Close()
        return
    }
    sig_str := bash_script[0]
    
    var signature []byte
    signature, err := hex.DecodeString(sig_str)
    if err != nil {
        fmt.Println(err)
        connection.Write([]byte("Server error, closing connection.\n"))
        connection.Close()
        return
    } 

    filename, err := Write_to_file(connection.RemoteAddr().String(), bash_script[1:])
    if err != nil {
        fmt.Println(err)
        connection.Write([]byte("Server error, closing connection.\n"))
        connection.Close()
        err = Rm_file(filename)
        if err != nil {
            fmt.Println(err)
        }
        return
    }
    
    file_hash, err := Get_hash(filename)
    if err != nil {
        fmt.Println(err)
        connection.Write([]byte("Server error, closing connection.\n"))
        connection.Close()
        err = Rm_file(filename)
        if err != nil {
            fmt.Println(err)
        }
        return
    }

    certs, err := os.ReadDir("certs")
    if err != nil {
        fmt.Println(err)
        connection.Write([]byte("Server error, closing connection.\n"))
        connection.Close()
        err = Rm_file(filename)
        if err != nil {
            fmt.Println(err)
        }
        return
    }
    should_run := 0
    for _, cert := range certs {
        should_run, err = Check_signature(cert.Name(), signature, file_hash)
        if err != nil && verbose {
            fmt.Println(err)
            fmt.Printf("Error processing signature from %s using certificate %s.\n", connection.RemoteAddr().String(), cert.Name())
        }
        if should_run == 1 {
            fmt.Printf("Signature from %s verified using certificate %s.\n", connection.RemoteAddr().String(), cert.Name())
            break
        }
    }

    if should_run == 1 {
        err := Make_exec(filename)   // only make executable after verifying signature
        if err != nil {
            fmt.Println(err)
            connection.Write([]byte("Server error, closing connection.\n"))
            connection.Close()
            err = Rm_file(filename)
            if err != nil {
                fmt.Println(err)
            }
            return
        }
        output, err := Exec_bash(filename)
        if err != nil {
            fmt.Printf("Error running bash script sent by %s: ", connection.RemoteAddr().String())
            fmt.Printf("%s, closing connection.\n", err)
            connection.Write([]byte("Invalid bash script sent, closing connection.\n"))
            connection.Close()
            err = Rm_file(filename)
            if err != nil {
                fmt.Println(err)
            }
            return
        }
        fmt.Printf("Signature and code from %s valid, output:\n", connection.RemoteAddr().String())
        fmt.Println(output)
        fmt.Printf("End of output from %s, closing connection.\n", connection.RemoteAddr().String())
        connection.Write([]byte("Signature verified, script output:\n"))
        connection.Write([]byte(output)) 
        err = Rm_file(filename)
        if err != nil {
            fmt.Println(err)
        }
        connection.Close()
        return
    }
    fmt.Printf("Signature recieved from %s does not match any local certificates, closing connection.\n", connection.RemoteAddr().String())
    connection.Write([]byte("Invalid signature recieved.\n"))
    connection.Close()
    err = Rm_file(filename)
    if err != nil {
        fmt.Println(err)
    }
    return
}
