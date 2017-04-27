//package for testing with the caida packet traces
package caida

import (
	"bufio"
	"os"
	"strconv"
	"time"
)

const (
	//the file that contains the output of extract_packets.c
	filename = "output_long.txt"
	numPkts = 11519046
)

var (
	f *os.File
	scanner *bufio.Scanner
	packets [numPkts](*caidaPkt)
)

//encapsulates the information of one "packet" of the output.txt file
type caidaPkt struct {
	duration time.Duration
	id [12]byte
	size uint32
}

//function for handling errors
func checkErr(e error) {
	if e != nil {
		panic(e)
	}
}

func populatePackets() {
	//open the output.txt file
	f, err := os.Open(filename)
	checkErr(err)

	//get a scanner
	scanner = bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	for cp, i := nextPkt(), 0; cp != nil && i < numPkts; i++ {
		packets[i] = cp
		cp = nextPkt()
	}
	
	f.Close()
}

//function that will parse the next line of the output.txt file and give back a "packet"
func nextPkt() *caidaPkt {
	cPkt := &caidaPkt{}

	var err error
	var temp uint64
	var timestamp_sec, timestamp_usec int //sec, micro sec	
	if (scanner.Scan()) {
		timestamp_sec, err = strconv.Atoi(scanner.Text())
		checkErr(err)
		scanner.Scan()

		timestamp_usec, err = strconv.Atoi(scanner.Text())
		checkErr(err)
		scanner.Scan()
		cPkt.duration = time.Unix(int64(timestamp_sec), 
			int64(timestamp_usec * 1000)).Sub(time.Unix(0, 0))

		if (copy(cPkt.id[:], []byte(scanner.Text())[:12]) != 12) {
			panic("caida: Wrong number of bytes copied!")
		}
		scanner.Scan()

		temp, err = strconv.ParseUint(scanner.Text(), 10, 32)
		cPkt.size = uint32(temp)
		checkErr(err)
		return cPkt
	} else {
		return nil
	}
}


