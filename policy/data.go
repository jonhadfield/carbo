package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/jonhadfield/carbo/helpers"
	"github.com/jonhadfield/carbo/session"
	"github.com/sirupsen/logrus"
	"github.com/ztrue/tracerr"
	"io/fs"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/frontdoor/mgmt/frontdoor"
)

// GetFrontDoorByID returns a front door instance for the provided id.
// it includes endpoints with any associated waf policies.
func GetFrontDoorByID(s *session.Session, frontDoorID string) (frontDoor FrontDoor, err error) {
	ctx := context.Background()

	rID := ParseResourceID(frontDoorID)

	rawFrontDoor, err := s.FrontDoorsClients[rID.SubscriptionID].Get(ctx, rID.ResourceGroup, rID.Name)
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

				wafPolicy, err = GetRawPolicy(s, rID.SubscriptionID, rid.ResourceGroup, rid.Name)
				if err != nil {
					return
				}

				policies[*e.WebApplicationFirewallPolicyLink.ID] = wafPolicy
			} else {
				wafPolicy = val
			}

			frontDoorEndpoints = append(frontDoorEndpoints, FrontDoorEndpoint{
				Name:      *e.Name,
				hostName:  *e.HostName,
				WafPolicy: wafPolicy,
			})
		}
	}

	return FrontDoor{
		Name:      *rawFrontDoor.Name,
		Endpoints: frontDoorEndpoints,
	}, err
}

type FrontDoorEndpoint struct {
	Name      string
	hostName  string
	WafPolicy frontdoor.WebApplicationFirewallPolicy
}

type FrontDoor struct {
	Name      string
	Endpoints []FrontDoorEndpoint
}

type FrontDoors []FrontDoor

type ResourceID struct {
	SubscriptionID string
	ResourceGroup  string
	Provider       string
	Name           string
	Raw            string
}

type Action struct {
	ActionType string `yaml:"action"`
	Policy     string
	Paths      []string `yaml:"paths"`
	MaxRules   int      `yaml:"max-rules"`
	Nets       IPNets
}

func LoadActionsFromPath(f string) (actions []Action, err error) {
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

			ipns, err = LoadIPsFromPath(p)
			if err != nil {
				return
			}

			a.Nets = append(a.Nets, ipns...)
		}

		actions = append(actions, a)
	}

	return
}

func LoadBackupsFromPath(paths []string) (wps []WrappedPolicy, err error) {
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
			wp, err = LoadWrappedPolicyFromFile(filepath.Join(cwd, info.Name()))
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

					wp, err = LoadWrappedPolicyFromFile(filepath.Join(path, info.Name()))

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
		Raw:            rawID,
	}
}

func LoadWrappedPolicyFromFile(f string) (wp WrappedPolicy, err error) {
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

// applyIPChanges updates an existing custom policy with IPs matching the requested action
func applyIPChanges(s *session.Session, input ApplyIPsInput) (err error) {
	prefix, err := helpers.PrefixFromAction(input.Action)
	if err != nil {
		return
	}

	lowercaseAction := strings.ToLower(input.Action)

	if input.Filepath != "" {
		var fipns IPNets

		fipns, err = LoadIPsFromPath(input.Filepath)
		if err != nil {
			return
		}

		input.Nets = append(input.Nets, fipns...)
	}

	if len(input.Nets) == 0 {
		return fmt.Errorf("no IPs loaded")
	}

	var p frontdoor.WebApplicationFirewallPolicy

	subscription := input.RID.SubscriptionID
	resourceGroup := input.RID.ResourceGroup
	name := input.RID.Name

	// check if Policy exists
	p, err = GetRawPolicy(s, subscription, resourceGroup, name)
	if err != nil {
		return err
	}

	if p.Name == nil {
		return fmt.Errorf("specified Policy not found")
	}

	// take a copy of the Policy for later comparison
	origPolicyJSON, err := json.MarshalIndent(p, "", "    ")
	if err != nil {
		return
	}

	crs, err := GenCustomRulesFromIPNets(input.Nets, input.MaxRules, input.Action)
	if err != nil {
		return
	}

	// remove existing net rules from Policy before adding New
	var ecrs []frontdoor.CustomRule

	for _, existingCustomRule := range *p.CustomRules.Rules {
		// if New custom rule name doesn't have the prefix in the Action, then add it
		// this means all the ones not matching the action go at the beginning #### WRONG BEHAVIOUR - MUST BE IN PRIORITY ORDER
		if !strings.HasPrefix(*existingCustomRule.Name, prefix) {
			ecrs = append(ecrs, existingCustomRule)
		}
	}

	// New rule list
	// for existing-rule in existing-rules
	//		for New rule in New rules
	//			  if existing-rule.priority < New-rule.priority:
	//					New-rule-list = append(New-rule-list

	// add the New custom rules to the existing
	*p.CustomRules.Rules = append(ecrs, crs...)
	// check we don't exceed Azure rules limit
	if len(*p.CustomRules.Rules) > helpers.MaxCustomRules {
		return fmt.Errorf("operation exceededs custom rules limit of %d", helpers.MaxCustomRules)
	}
	//
	// // check we don't exceed the user specified max rules limit
	// if len(*p.CustomRules.Rules) > input.MaxRules {
	//	return fmt.Errorf("operation exceededs custom rules limit of %d", MaxCustomRules)
	// }

	// SortRules(*p.CustomRules.Rules)
	// check if rules differ from Original
	// num, patch, err := GeneratePolicyPatch(origPolicyJSON, p)
	gppO, err := GeneratePolicyPatch(GeneratePolicyPatchInput{Original: origPolicyJSON, New: p})
	if err != nil {
		return err
	}

	if gppO.CustomRuleChanges == 0 {
		log.Println("nothing to do")

		return nil
	}

	if input.DryRun {
		log.Printf("%d changes to %s list would be applied\n", gppO.CustomRuleChanges, lowercaseAction)

		return nil
	}

	if input.Output {
		o, _ := json.MarshalIndent(p, "", "    ")
		fmt.Println(string(o))

		return nil
	}

	log.Printf("updating Policy %s\n", *p.Name)

	err = PushPolicy(s, PushPolicyInput{
		Name:          *p.Name,
		Subscription:  input.RID.SubscriptionID,
		ResourceGroup: input.RID.ResourceGroup,
		Policy:        p,
	})

	if err == nil {
		fmt.Printf("%d changes to %s list have been applied\n", gppO.CustomRuleChanges, lowercaseAction)
	}

	return err
}

// ApplyIPChanges accepts user input specifying IPs, or filepath containing IPs, and then adds them to custom rules
// matching the specified action
func ApplyIPChanges(input ApplyIPsInput) (err error) {
	s := session.Session{}

	return applyIPChanges(&s, input)
}

func ParseResourceIDs(rawIDs []string) (res []ResourceID) {
	for _, rid := range rawIDs {
		res = append(res, ParseResourceID(rid))
	}

	return
}

func GetResourceIDsFromGenericResources(gres []resources.GenericResourceExpanded) (rids []ResourceID) {
	for _, gre := range gres {
		rids = append(rids, ParseResourceID(*gre.ID))
	}

	return
}
