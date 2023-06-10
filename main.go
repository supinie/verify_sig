package main

import (
	"supinie/sig_verify_server/lib"

	"flag"
	"fmt"
    "net"
    "strconv"
)

func main() {
    var port int
    var verbose bool

    flag.IntVar(&port, "p", 0, "Choose the port for the server to listen on. Default will be a random available port.")
    flag.BoolVar(&verbose, "v", false, "Specify the verbosity of the outputs. This will give detailed feedback on the validity of every certificate check.")
    flag.Parse()

    listener, err := net.Listen("tcp4", ":" + strconv.Itoa(port))
    if err != nil {
        fmt.Println(err)
        return
    }
    fmt.Printf("Listening on %s\n", listener.Addr())

    defer listener.Close()
    for {
        connection, err := listener.Accept()
        if err != nil {
            fmt.Println(err)
            return
        }
        go lib.Take_Connection(connection, verbose)
    }
}
