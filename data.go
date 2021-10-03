package carbo

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"io/ioutil"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/ztrue/tracerr"
	"gopkg.in/yaml.v3"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/frontdoor/mgmt/frontdoor"
)

// getFrontDoorByID returns a front door instance for the provided id.
// it includes endpoints with any associated waf policies.
func getFrontDoorByID(s *session, frontDoorID string) (frontDoor FrontDoor, err error) {
	ctx := context.Background()

	rID := ParseResourceID(frontDoorID)

	rawFrontDoor, err := s.frontDoorsClients[rID.SubscriptionID].Get(ctx, rID.ResourceGroup, rID.Name)
	if err != nil {
		return
	}

	policies := make(map[string]frontdoor.WebApplicationFirewallPolicy)

	var frontDoorEndpoints []FrontDoorEndpoint

	for _, e := range *rawFrontDoor.FrontendEndpoints {
		if e.WebApplicationFirewallPolicyLink != nil && e.WebApplicationFirewallPolicyLink.ID != nil {
			var wafPolicy frontdoor.WebApplicationFirewallPolicy

			val, ok := policies[*e.WebApplicationFirewallPolicyLink.ID]
			if !ok {
				rid := ParseResourceID(*e.WebApplicationFirewallPolicyLink.ID)

				wafPolicy, err = s.getRawPolicy(rID.SubscriptionID, rid.ResourceGroup, rid.Name)
				if err != nil {
					return
				}

				policies[*e.WebApplicationFirewallPolicyLink.ID] = wafPolicy
			} else {
				wafPolicy = val
			}

			frontDoorEndpoints = append(frontDoorEndpoints, FrontDoorEndpoint{
				name:      *e.Name,
				hostName:  *e.HostName,
				wafPolicy: wafPolicy,
			})
		}
	}

	return FrontDoor{
		name:      *rawFrontDoor.Name,
		endpoints: frontDoorEndpoints,
	}, err
}

// pushPolicyInput defines the input for the pushPolicy function
type pushPolicyInput struct {
	Name           string
	subscription   string
	resourceGroup  string
	policy         frontdoor.WebApplicationFirewallPolicy
	Debug          bool
	Timeout        int64
	Async          bool
}

const (
	PushPolicyTimeout       = 120
	PushPolicyPollFrequency = 10
)

// pushPolicy creates or updates a waf policy with the provided policy instance.
func (s *session) pushPolicy(i pushPolicyInput) (err error) {
	var ctx context.Context
	if !i.Async {
		timeout := time.Duration(i.Timeout) * time.Second
		// if timeout not set, use the default
		if i.Timeout == 0 {
			timeout = PushPolicyTimeout * time.Second
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
		defer cancel()
		logrus.Debugf("using sync for policy push with timeout: %s", timeout.String())

		select {
		case <-time.After(PushPolicyPollFrequency * time.Second):
			fmt.Println("policy push in progress...")
		case <-ctx.Done():
			if err = ctx.Err(); err != nil {
				return err
			}

			return
		}
	} else {
		logrus.Debug("using async for policy push")
		ctx = context.Background()
	}

	// check we're not missing a policies client for the subscription
	err = s.getFrontDoorPoliciesClient(i.subscription)
	if err != nil {
		return
	}

	result, err := s.frontDoorPoliciesClients[i.subscription].CreateOrUpdate(ctx, i.resourceGroup, i.Name, i.policy)
	if err != nil {
		return
	}
	logrus.Debugf("policy push result: %s", result.Status())

	if i.Async {
		fmt.Println("policy push started asynchronously")

		return
	}

	fmt.Println("policy successfully pushed")

	return
}

type getWrappedPoliciesInput struct {
	subscriptionID    string
	appVersion        string
	filterResourceIDs []string
	max               int
}

type getWrappedPoliciesOutput struct {
	policies []WrappedPolicy
}

type FrontDoorEndpoint struct {
	name      string
	hostName  string
	wafPolicy frontdoor.WebApplicationFirewallPolicy
}

type FrontDoor struct {
	name      string
	endpoints []FrontDoorEndpoint
}

type FrontDoors []FrontDoor

type ResourceID struct {
	SubscriptionID string
	ResourceGroup  string
	Provider       string
	Name           string
	Raw            string
}

// ParseResourceID accepts an azure resource ID as a string and returns a struct instance containing the components.
func ParseResourceID(rawID string) ResourceID {
	components := strings.Split(rawID, "/")
	if len(components) != 9 {
		return ResourceID{}
	}

	return ResourceID{
		SubscriptionID: components[2],
		ResourceGroup:  components[4],
		Provider:       components[6],
		Name:           components[8],
	}
}

func ParseResourceIDs(rawIDs []string) (res []ResourceID) {
	for _, rid := range rawIDs {
		res = append(res, ParseResourceID(rid))
	}

	return
}

func loadWrappedPolicyFromFile(f string) (wp WrappedPolicy, err error) {
	var data []byte

	data, err = ioutil.ReadFile(f)
	if err != nil {
		err = tracerr.Wrap(err)

		return
	}

	err = json.Unmarshal(data, &wp)

	err = tracerr.Wrap(err)

	return
}

type Action struct {
	ActionType string `yaml:"action"`
	Policy     string
	Paths      []string `yaml:"paths"`
	MaxRules   int      `yaml:"max-rules"`
	Nets       IPNets
}

func loadActionsFromPath(f string) (actions []Action, err error) {
	var data []byte

	data, err = ioutil.ReadFile(f)
	if err != nil {
		return
	}

	var rawActions []Action

	err = yaml.Unmarshal(data, &rawActions)

	// get ipns
	for _, ra := range rawActions {
		a := ra

		for _, p := range ra.Paths {
			usr, _ := user.Current()

			dir := usr.HomeDir

			if p == "~" {
				// In case of "~", which won't be caught by the "else if"
				p = dir
			} else if strings.HasPrefix(p, "~/") {
				// Use strings.HasPrefix so we don't match paths like
				// "/something/~/something/"
				p = filepath.Join(dir, p[2:])
			}

			var ipns []net.IPNet

			ipns, err = loadIPsFromPath(p)
			if err != nil {
				return
			}

			a.Nets = append(a.Nets, ipns...)
		}

		actions = append(actions, a)
	}

	return
}

func loadBackupsFromPath(paths []string) (wps []WrappedPolicy, err error) {
	for _, path := range paths {
		var info fs.FileInfo

		info, err = os.Stat(path)
		if os.IsNotExist(err) {
			return
		}

		if !info.IsDir() {
			cwd, _ := os.Getwd()

			if !strings.EqualFold(filepath.Ext(info.Name()), ".json") {
				continue
			}

			var wp WrappedPolicy
			wp, err = loadWrappedPolicyFromFile(filepath.Join(cwd, info.Name()))
			if err != nil {
				return
			}

			wps = append(wps, wp)

			continue
		}

		if info.IsDir() {
			var files []fs.FileInfo

			files, err = ioutil.ReadDir(path)
			if err != nil {
				return
			}

			for _, file := range files {
				if !file.IsDir() {
					if !strings.EqualFold(filepath.Ext(file.Name()), ".json") {
						continue
					}

					var wp WrappedPolicy

					wp, err = loadWrappedPolicyFromFile(filepath.Join(path, info.Name()))

					if err != nil {
						return
					}

					wps = append(wps, wp)
				}
			}
		}
	}

	logrus.Debugf("loaded %d policy backups\n", len(wps))

	return
}
