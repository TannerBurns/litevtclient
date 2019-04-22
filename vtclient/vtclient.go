package vtclient

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/TannerBurns/litebalancer/litebalancer"
)

type VtClient struct {
	VtKey   string
	Reports Reports
}

type ReportResponse map[string]interface{}

type Reports map[string]map[string]interface{}

func (vt *VtClient) GetReport(args []interface{}) interface{} {
	client := &http.Client{}
	tmpArgs := args[0].([]interface{})
	var hashes []string
	for i := range tmpArgs {
		hashes = append(hashes, tmpArgs[i].(string))
	}
	url := "https://www.virustotal.com/vtapi/v2/file/report"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}

	q := req.URL.Query()
	q.Add("apikey", vt.VtKey)
	q.Add("resource", strings.Join(hashes, ","))
	//q.Add("allinfo", "1")
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal()
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		reports := make([]ReportResponse, 0)
		json.Unmarshal(body, &reports)
		for _, r := range reports {
			vt.Reports[r["sha256"].(string)] = make(map[string]interface{})
			vt.Reports[r["sha256"].(string)] = r
		}

	}
	time.Sleep(10 * time.Millisecond)
	return nil
}

func (vt *VtClient) GetReports(hashlist []string) (
	Reports,
	error,
) {
	const CHUNK = 24
	var groups = [][]string{}

	vt.Reports = make(map[string]map[string]interface{})

	for i := 0; i < len(hashlist); i += CHUNK {
		end := i + CHUNK

		if end > len(hashlist) {
			end = len(hashlist)
		}

		groups = append(groups, hashlist[i:end])
	}

	numRequesters := len(groups)
	numWorkers := numRequesters / 2

	rq, err := litebalancer.NewRequester(vt.GetReport)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(groups); i++ {
		g := make([]interface{}, len(groups[i]))
		for j, v := range groups[i] {
			g[j] = v
		}
		go rq.MakeRequest(rq.Work, g)
	}
	// run a new balancer to handle work
	litebalancer.NewBalancer(
		numRequesters,
		numWorkers,
		len(groups),
	).Balance(
		rq.Work,
	)
	time.Sleep(1 * time.Second)
	return vt.Reports, nil
}
