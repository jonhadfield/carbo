package backup

import (
	"github.com/jonhadfield/carbo/policy"
)

type RestorePoliciesInput struct {
	SubscriptionID   string
	BackupsPaths     []string
	CustomRulesOnly  bool
	ManagedRulesOnly bool
	TargetPolicy     string
	ResourceGroup    string
	RIDs             []policy.ResourceID
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
