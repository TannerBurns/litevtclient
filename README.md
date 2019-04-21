# GoVtClient

    VirusTotal Client written in go.

    Pros:
        Ability to scale with load. 
        The more resources to retrieve the more resources that will be 
        allocated to the load balancer
    
    Current Functionality:
        Pull reports for a list of hashes

# Requirements

	go get github.com/TannerBurns/litebalancer/litebalancer

# Example

    hashes.txt

```txt
41b39aee40f35afb1621b7787cd8c33646d81a8f72924ff4deec04d5bd4799cd
a8ad709cb6b81bd9d080c03870414d19429e23212bb9348069e9f1ab3870c5ba
939e84ca459cd2c4527ecc8ebe7321aea15cc4d77a0c999e57e57174156d3efd
aeed1dba9dd801c33376bfe3f37a8df49fff813aef0ff0b792c9da1d7a874641
af6cb6d7d81cc93d1eaa080ae8d8b0e66e5e004b529a310082b96691125bb66b
f10d64daa834a5c14e6829ff6dd686dff424d7554cc1ecd83870210c7cadd61f
1fae949274bb75b8413e5b7f491a4f1e9239be169dcfcf0988c5e38b9f3b47ac
563a69c349b98649c909f25fdc46dc0e1f5e80fad4f549a9575a8cbd439fdaeb
dd7431146af1cc5c2e3d3018277ba781f3e92815de695e1ccd849b2099cbf721
6a3d4abd103f22771a0ccb09b5df72563e153c328b310ead47d95a61d25a65f6
...
```

    main.go - write all reports to a single json file

```go
package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"github.com/TannerBurns/litevtclient/vtclient"
)

func main() {
	hashesPath := "./hashes.txt"
	client := vtclient.VtClient{
		VtKey: "VIRUSTOTALAPIKEY",
	}
	raw, err := ioutil.ReadFile(hashesPath)
	if err != nil {
		log.Fatal(err)
	}

	hashlist := strings.Split(string(raw), "\n")
	reports, err := client.GetReports(hashlist)
	if err != nil {
		log.Fatal(err)
	}
	time.Sleep(1 * time.Second)
	byteOut, err := json.MarshalIndent(reports, "", "    ")
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("output.json", byteOut, 0644)
	if err != nil {
		log.Fatal(err)
	}
}

```