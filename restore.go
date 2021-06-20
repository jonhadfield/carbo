package carbo

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/ztrue/tracerr"
)

type RestorePoliciesInput struct {
	SubscriptionID   string
	BackupsPaths     []string
	CustomRulesOnly  bool
	ManagedRulesOnly bool
	TargetPolicy     string
	ResourceGroup    string
	RIDs             []ResourceID
	Force            bool
	FailFast         bool
	Quiet            bool
	Debug            bool
}

// TODO: rGroup would be to override the resource group (in the filename) to restore to
// func restorePolicy(subID, rGroup, name string, failFast, quiet bool, path string) (err error) {
//	t := time.Now().UTC().Format("20060102150405")
//	var p frontdoor.WebApplicationFirewallPolicy
//
//	var cwd string
//
//	if !quiet {
//		cwd, err = os.Getwd()
//		if err != nil {
//			return
//		}
//		msg := fmt.Sprintf("backing up Policy: %s", name)
//		statusOutput := PadToWidth(msg, " ", 0, true)
//		width, _, _ := terminal.GetSize(0)
//		if len(statusOutput) == width {
//			fmt.Printf(statusOutput[0:width-3] + "   \r")
//		} else {
//			fmt.Print(statusOutput)
//		}
//
//	}
//	p, err = getRawPolicy(subID, rGroup, name)
//	if err != nil {
//		if failFast {
//			return err
//		}
//		log.Println(err)
//	}
//
//	var pj []byte
//	pj, err = json.MarshalIndent(p, "", "    ")
//	if err != nil {
//		if failFast {
//			return err
//		}
//		log.Println(err)
//	}
//	fName := fmt.Sprintf("%s+%s+%s+%s.json", subID, rGroup, name, t)
//	var f *os.File
//	fp := filepath.Join(path, fName)
//	f, err = os.Create(fp)
//	if err != nil {
//		return
//	}
//	_, err = f.Write(pj)
//	if err != nil {
//		f.Close()
//		return
//	}
//
//	_ = f.Close()
//
//	if !quiet {
//		op := filepath.Clean(fp)
//		if strings.HasPrefix(op, cwd) {
//			op, err = filepath.Rel(cwd, op)
//			if err != nil {
//				return
//			}
//			op = "./" + op
//		}
//		log.Printf("restore written to: %s", op)
//	}
//	return
//
// }

func (i RestorePoliciesInput) validate() error {
	if i.TargetPolicy != "" {
		if ValidateResourceID(i.TargetPolicy, false) != nil {
			return fmt.Errorf("target policy '%s' is invalid", i.TargetPolicy)
		}
	}

	return nil
}

// RestorePolicies loads existing backup(s) from files and then adds/overwrites based on user's choices
func RestorePolicies(i RestorePoliciesInput) (err error) {
	if err = i.validate(); err != nil {
		return
	}

	// load policies from path
	wps, err := loadBackupsFromPath(i.BackupsPaths)
	if err != nil {
		return tracerr.Wrap(err)
	}

	if len(wps) == 0 {
		return fmt.Errorf("no backup files could be found in paths: %s", strings.Join(i.BackupsPaths, ", "))
	}

	// ensure only single backup file loaded if targetting a policy
	if i.TargetPolicy != "" && len(wps) > 1 {
		return fmt.Errorf("restoring more than one backup to a single policy doesn't make sense")
	}

	// if no target policy specified, then retrieve from backup
	if i.TargetPolicy == "" {
		i.TargetPolicy = wps[0].PolicyID
		logrus.Debugf("retrieved target id from backup: %s", i.TargetPolicy)
	}

	s := session{}

	// restore loaded backups
	policies, err := getPoliciesToRestore(&s, wps, i)
	if err != nil {
		return
	}

	if len(policies) > 0 {
		// if target policy specified, there can be only one
		if i.TargetPolicy != "" {
			rID := ParseResourceID(i.TargetPolicy)
			policies[0].SubscriptionID = rID.SubscriptionID
			policies[0].ResourceGroup = rID.ResourceGroup
			policies[0].Name = rID.Name
		}

		for _, policy := range policies {
			err = s.pushPolicy(pushPolicyInput{
				Name:          policy.Name,
				subscription:  policy.SubscriptionID,
				resourceGroup: policy.ResourceGroup,
				policy:        policy.Policy,
			})
			if err != nil {
				return
			}
		}
	}

	return
}
