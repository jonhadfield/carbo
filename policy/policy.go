package policy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/jonhadfield/carbo/helpers"
	"github.com/jonhadfield/carbo/session"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io/fs"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/frontdoor/mgmt/frontdoor"
)

func ListPolicies(subID, appVersion string, max int) error {
	if max == 0 {
		return fmt.Errorf("invalid maximum number of policies to return")
	}

	s := session.Session{}

	o, err := GetAllPolicies(&s, GetWrappedPoliciesInput{
		SubscriptionID:    subID,
		AppVersion:        appVersion,
		Max:               max,
		FilterResourceIDs: nil,
	})
	if err != nil {
		return err
	}

	if len(o) == 0 {
		fmt.Println("no policies found")

		return nil
	}

	// print the policy ids
	for _, p := range o {
		fmt.Println(*p.ID)
	}

	return nil
}

// MatchExistingPolicyByID returns the raw policy matched by the policy id of its origin, e.g. where the backup was from
func MatchExistingPolicyByID(targetPolicyID string, existingPolicies []WrappedPolicy) (found bool, policy WrappedPolicy) {
	for x := range existingPolicies {
		if strings.EqualFold(existingPolicies[x].PolicyID, targetPolicyID) {
			return true, existingPolicies[x]
		}
	}

	return
}

type WrappedPolicy struct {
	Date           time.Time
	SubscriptionID string
	ResourceGroup  string
	Name           string
	Policy         frontdoor.WebApplicationFirewallPolicy
	PolicyID       string
	AppVersion     string
}

func DeleteCustomRules(dcri DeleteCustomRulesInput) (err error) {
	// preflight checks
	s := session.Session{}

	return deleteCustomRules(&s, dcri)
}

func deleteCustomRules(s *session.Session, dcri DeleteCustomRulesInput) (err error) {
	var p frontdoor.WebApplicationFirewallPolicy

	subscription := dcri.RID.SubscriptionID
	resourceGroup := dcri.RID.ResourceGroup
	name := dcri.RID.Name

	// check if Policy exists
	p, err = GetRawPolicy(s, subscription, resourceGroup, name)
	if err != nil {
		return err
	}

	if p.Name == nil {
		return fmt.Errorf("specified Policy not found")
	}

	// remove all but those starting with supplied prefix
	preLen := len(*p.CustomRules.Rules)

	var ecrs []frontdoor.CustomRule

	for _, cr := range *p.CustomRules.Rules {
		if !strings.HasPrefix(*cr.Name, dcri.Prefix) {
			ecrs = append(ecrs, cr)
		}
	}

	if len(ecrs) == preLen {
		log.Println("nothing to do")

		return nil
	}

	*p.CustomRules.Rules = ecrs

	log.Printf("updating Policy %s\n", *p.Name)

	err = PushPolicy(s, PushPolicyInput{
		Name:          *p.Name,
		Subscription:  dcri.RID.SubscriptionID,
		ResourceGroup: dcri.RID.ResourceGroup,
		Policy:        p,
		Debug:         dcri.Debug,
	})

	return err
}

type DeleteCustomRulesInput struct {
	RID      ResourceID
	Prefix   string
	MaxRules int
	Debug    bool
}

// PrintPolicyCustomRule outputs the custom rule for a given resource.
// the id is an extended resource id: <policy>|<custom rule name>.
func PrintPolicyCustomRule(id string) error {
	s := session.Session{}

	cr, err := GetRawPolicyCustomRuleByID(&s, id)
	if err != nil {
		return err
	}

	var b []byte

	b, err = json.MarshalIndent(cr, "", "    ")
	if err != nil {
		return errors.Wrap(err, "failed to marshall custom rule")
	}

	fmt.Println(string(b))

	return nil
}

// GetRawPolicyCustomRuleByID returns a custom rule matching the resource id.
// the id is an extended resource id: <policy>|<custom rule name>.
func GetRawPolicyCustomRuleByID(s *session.Session, id string) (pcr frontdoor.CustomRule, err error) {
	pid, ruleName, err := helpers.SplitExtendedID(id)
	if err != nil {
		return
	}

	rid := ParseResourceID(pid)

	p, err := GetRawPolicy(s, rid.SubscriptionID, rid.ResourceGroup, rid.Name)
	if err != nil {
		return pcr, err
	}

	for _, r := range *p.CustomRules.Rules {
		if *r.Name == ruleName {
			pcr = r

			break
		}
	}

	if pcr.Name == nil {
		return pcr, fmt.Errorf("custom rule '%s' not found", ruleName)
	}

	return
}

// LoadIPsFromPath accepts a file path or directory and then generates a fully qualified path
// in order to call a function to load the ips from each fully qualified file path
func LoadIPsFromPath(path string) (ipNets IPNets, err error) {
	// if path is a folder, then loop through contents
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return
	}

	if info.IsDir() {
		var files []fs.FileInfo

		files, err = ioutil.ReadDir(path)
		if err != nil {
			return
		}

		for _, file := range files {
			if !file.IsDir() {
				var n IPNets

				p := filepath.Join(path, file.Name())

				n, err = ReadIPsFromFile(p)
				if err != nil {
					return
				}

				logrus.Printf("loaded %d ips from file %s\n", len(n), p)

				ipNets = append(ipNets, n...)
			}
		}

		return
	}

	var n IPNets

	n, err = ReadIPsFromFile(path)
	if err != nil {
		return
	}

	logrus.Debugf("loaded %d ips from file %s\n", len(n), path)

	ipNets = append(ipNets, n...)

	return
}

// ReadIPsFromFile accepts a file path from which to load IPs (one per line) as strings and return a slice of
func ReadIPsFromFile(fPath string) (ipnets IPNets, err error) {
	file, err := os.Open(fPath)
	if err != nil {
		log.Fatalf("failed to open")
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	var ipnet *net.IPNet

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "#") {
			if !strings.Contains(line, "/") {
				line = line + "/32"
			}

			_, ipnet, err = net.ParseCIDR(line)
			if err != nil {
				return
			}

			ipnets = append(ipnets, *ipnet)
		}
	}

	return
}
