package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/storage/mgmt/storage"
	"github.com/Azure/azure-storage-blob-go/azblob"
	"github.com/jonhadfield/carbo/helpers"
	"github.com/jonhadfield/carbo/policy"
	"github.com/jonhadfield/carbo/session"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/ztrue/tracerr"

	terminal "golang.org/x/term"
)

// BackupPoliciesInput are the arguments provided to the BackupPolicies function.
type BackupPoliciesInput struct {
	SubscriptionID           string
	Path                     string
	AppVersion               string
	RIDs                     []string
	StorageAccountResourceID string
	ContainerURL             string
	FailFast                 bool
	Quiet                    bool
	Debug                    bool
}

// BackupPolicies retrieves policies within a subscription and writes them, with meta-data, to individual json files
func BackupPolicies(i BackupPoliciesInput) error {
	s := session.Session{}

	// fail if only one of the storage account destination required parameters been defined
	if (i.StorageAccountResourceID != "" && i.ContainerURL == "") || (i.StorageAccountResourceID == "" && i.ContainerURL != "") {
		return fmt.Errorf("both storage account resource id and container url are required for backups to Azure Storage")
	}

	// fail if neither path nor storage account details are provided
	if i.StorageAccountResourceID == "" && i.Path == "" {
		return fmt.Errorf("either path or storage account details are required")
	}

	if len(i.RIDs) == 0 && i.SubscriptionID == "" {
		return fmt.Errorf("either subscription id or resource ids are required")
	}

	o, err := policy.GetWrappedPolicies(&s, policy.GetWrappedPoliciesInput{
		SubscriptionID:    i.SubscriptionID,
		AppVersion:        i.AppVersion,
		FilterResourceIDs: i.RIDs,
	})
	if err != nil {
		return err
	}

	logrus.Debugf("retrieved %d policies", len(o.Policies))

	var containerURL azblob.ContainerURL
	if i.StorageAccountResourceID != "" {
		sari := policy.ParseResourceID(i.StorageAccountResourceID)
		storageAccountsClient := storage.NewAccountsClient(sari.SubscriptionID)
		storageAccountsClient.Authorizer = *s.Authorizer
		ctx := context.Background()
		var sac storage.AccountListKeysResult
		sac, err = storageAccountsClient.ListKeys(ctx, sari.ResourceGroup, sari.Name, "")
		if err != nil {
			return tracerr.Wrap(err)
		}

		keys := *sac.Keys
		b := keys[0]
		credential, err := azblob.NewSharedKeyCredential(sari.Name, *b.Value)
		if err != nil {
			log.Fatal("invalid credentials with error: " + err.Error())
		}
		p := azblob.NewPipeline(credential, azblob.PipelineOptions{})

		cu, err := url.Parse(i.ContainerURL)
		if err != nil {
			return err
		}

		containerURL = azblob.NewContainerURL(*cu, p)
	}

	return backupPolicies(o.Policies, containerURL, i.FailFast, i.Quiet, i.Path)
}

// backupPolicy takes a WrappedPolicy as input and creates a json file that can later be restored
func backupPolicy(policy policy.WrappedPolicy, containerURL azblob.ContainerURL, failFast, quiet bool, path string) (err error) {
	t := time.Now().UTC().Format("20060102150405")

	var cwd string

	if !quiet {
		cwd, err = os.Getwd()
		if err != nil {
			return
		}

		msg := fmt.Sprintf("backing up Policy: %s", policy.Name)
		statusOutput := helpers.PadToWidth(msg, " ", 0, true)
		width, _, _ := terminal.GetSize(0)

		if len(statusOutput) == width {
			fmt.Printf(statusOutput[0:width-3] + "   \r")
		} else {
			fmt.Print(statusOutput)
		}
	}

	var pj []byte

	pj, err = json.MarshalIndent(policy, "", "    ")
	if err != nil {
		if failFast {
			return tracerr.Wrap(err)
		}

		log.Println(err)
	}

	fName := fmt.Sprintf("%s+%s+%s+%s.json", policy.SubscriptionID, policy.ResourceGroup, policy.Name, t)

	// write to storage account
	if containerURL.String() != "" {
		ctx := context.Background()
		blobURL := containerURL.NewBlockBlobURL(fName)
		if !quiet {
			fmt.Printf("uploading file with blob name: %s\n", fName)
		}
		_, err = azblob.UploadBufferToBlockBlob(ctx, pj, blobURL, azblob.UploadToBlockBlobOptions{
			BlockSize:   4 * 1024 * 1024,
			Parallelism: 16})
		if err != nil {
			return err
		}
	}

	if path != "" {
		err = writeBackupToFile(pj, cwd, fName, quiet, path)
		if err != nil {
			return
		}
	}

	return
}

func writeBackupToFile(pj []byte, cwd string, fName string, quiet bool, path string) (err error) {
	var f *os.File

	fp := filepath.Join(path, fName)
	f, err = os.Create(fp)

	if err != nil {
		return
	}

	_, err = f.Write(pj)
	if err != nil {
		f.Close()

		return
	}

	_ = f.Close()

	if !quiet {
		op := filepath.Clean(fp)
		if strings.HasPrefix(op, cwd) {
			op, err = filepath.Rel(cwd, op)
			if err != nil {
				return
			}

			op = "./" + op
		}

		fmt.Printf("backup written to: %s\n", op)
	}

	return
}

// backupPolicies accepts a list of WrappedPolicys and calls backupPolicy with each
func backupPolicies(policies []policy.WrappedPolicy, containerURL azblob.ContainerURL, failFast, quiet bool, path string) (err error) {
	for _, p := range policies {
		err = backupPolicy(p, containerURL, failFast, quiet, path)

		if failFast {
			return
		}
	}

	return
}

// RestorePolicies loads existing backup(s) from files and then adds/overwrites based on user's choices
func RestorePolicies(i RestorePoliciesInput) (err error) {
	if err = i.Validate(); err != nil {
		return
	}

	// load policies from path
	wps, err := policy.LoadBackupsFromPath(i.BackupsPaths)
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

	s := session.Session{}

	// restore loaded backups
	policies, err := GetPoliciesToRestore(&s, wps, i)
	if err != nil {
		return
	}

	if len(policies) > 0 {
		// if target policy specified, there can be only one
		if i.TargetPolicy != "" {
			rID := policy.ParseResourceID(i.TargetPolicy)
			policies[0].SubscriptionID = rID.SubscriptionID
			policies[0].ResourceGroup = rID.ResourceGroup
			policies[0].Name = rID.Name
		}

		for _, p := range policies {
			err = policy.PushPolicy(&s, policy.PushPolicyInput{
				Name:          p.Name,
				Subscription:  p.SubscriptionID,
				ResourceGroup: p.ResourceGroup,
				Policy:        p.Policy,
			})
			if err != nil {
				return
			}
		}
	}

	return
}

func (i RestorePoliciesInput) Validate() error {
	if i.TargetPolicy != "" {
		if helpers.ValidateResourceID(i.TargetPolicy, false) != nil {
			return fmt.Errorf("target policy '%s' is invalid", i.TargetPolicy)
		}
	}

	return nil
}

func GetPoliciesToRestore(s *session.Session, policyBackups []policy.WrappedPolicy, i RestorePoliciesInput) (policiesToRestore []policy.WrappedPolicy, err error) {
	// get all existing policies in subscription, filtered by target policy id if provided
	var filterResourceIDs []string
	if i.TargetPolicy != "" {
		filterResourceIDs = []string{i.TargetPolicy}
	}

	logrus.Debugf("retrieving target policy: %s", i.TargetPolicy)
	o, err := policy.GetWrappedPolicies(s, policy.GetWrappedPoliciesInput{
		FilterResourceIDs: filterResourceIDs,
		SubscriptionID:    i.SubscriptionID,
	})
	if err != nil {
		return policiesToRestore, tracerr.Wrap(err)
	}

	existingPolicies := o.Policies

	// compare each backup policy id (or target policy id if provided) with existing policy ids
	for _, policyBackup := range policyBackups {
		matchPolicyID := policyBackup.PolicyID
		if i.TargetPolicy != "" {
			matchPolicyID = i.TargetPolicy
		}

		var foundExisting bool

		var matchedExistingPolicy policy.WrappedPolicy

		foundExisting, matchedExistingPolicy = policy.MatchExistingPolicyByID(matchPolicyID, existingPolicies)

		if foundExisting {
			// var gppInput GeneratePolicyPatchInput
			var output policy.GeneratePolicyPatchOutput

			output, err = policy.GeneratePolicyPatch(
				policy.GeneratePolicyPatchInput{
					Original: matchedExistingPolicy,
					New:      policyBackup.Policy,
				})
			if err != nil {
				return
			}

			if i.CustomRulesOnly && output.CustomRuleChanges == 0 {
				fmt.Println("target policy's custom rules are identical to those in backup")

				continue
			}

			if i.ManagedRulesOnly && output.ManagedRuleChanges == 0 {
				fmt.Println("target policy's managed rules are identical to those in backup")

				continue
			}

			if output.TotalRuleDifferences == 0 {
				fmt.Println("target policy rules are identical to backup")

				continue
			}
		}

		var op string
		if i.CustomRulesOnly {
			op = "custom "
		}

		if i.ManagedRulesOnly {
			op = "managed "
		}

		switch {
		case i.TargetPolicy != "" && !foundExisting:
			// if targeted policy wasn't found, return error
			err = fmt.Errorf("target policy does not exist")

		case i.TargetPolicy != "" && foundExisting && !i.Force:
			// if targeted policy was found, but not forced, then ask before replacing
			if i.TargetPolicy != "" && !helpers.Confirm(fmt.Sprintf("confirm replacement of %srules in target policy %s", op, i.TargetPolicy),
				fmt.Sprintf("with backup %s\ntaken %v",
					policyBackup.PolicyID,
					policyBackup.Date.Format(time.RFC850),
				)) {

				continue
			}
		case i.TargetPolicy == "" && foundExisting && !i.Force:
			// if non-targeted match found, then ask user if they want to replace rules
			if !helpers.Confirm(fmt.Sprintf("found an existing policy: %s", matchedExistingPolicy.PolicyID),
				fmt.Sprintf("confirm replacement of %srules with backup taken %v", op, policyBackup.Date.Format(time.RFC850))) {

				continue
			}
		case matchedExistingPolicy.PolicyID == "" && i.ResourceGroup == "":
			// if we need to create a New policy we need a resource group to be specified
			err = fmt.Errorf("unable to create New policy without specifying its resource group")

		default:
			err = fmt.Errorf("unexpected restore operation")
		}

		if err != nil {
			return
		}

		// policy is either:
		// - existing and user confirmed replacement
		// - existing and user chose to force apply
		// - New, and safe to apply
		policyToRestore := GeneratePolicyToRestore(matchedExistingPolicy, policyBackup, i)

		policiesToRestore = append(policiesToRestore, policyToRestore)
	}

	return
}

// GeneratePolicyToRestore accepts two policies (Original and backup) and options on which parts (custom and or managed rules) to replace
// without options, the Original will have both custom and managed rules parts replaced
// options allow for custom or managed rules in Original to replaced with those in backup
func GeneratePolicyToRestore(existing policy.WrappedPolicy, backup policy.WrappedPolicy, i RestorePoliciesInput) policy.WrappedPolicy {
	// if there isn't an existing policy, then just add backup
	if existing.PolicyID == "" {
		return policy.WrappedPolicy{
			SubscriptionID: i.SubscriptionID,
			ResourceGroup:  i.ResourceGroup,
			Name:           backup.Name,
			Policy:         backup.Policy,
		}
	}

	switch {
	case i.CustomRulesOnly:
		existing.Policy.CustomRules.Rules = backup.Policy.CustomRules.Rules
		rID := policy.ParseResourceID(existing.PolicyID)

		return policy.WrappedPolicy{
			SubscriptionID: rID.SubscriptionID,
			ResourceGroup:  rID.ResourceGroup,
			Name:           rID.Name,
			Policy:         existing.Policy,
			PolicyID:       existing.PolicyID,
		}
	case i.ManagedRulesOnly:
		if backup.Policy.ManagedRules == nil {
			existing.Policy.ManagedRules = nil
		} else {
			existing.Policy.ManagedRules = backup.Policy.ManagedRules
		}

		rID := policy.ParseResourceID(existing.PolicyID)

		return policy.WrappedPolicy{
			SubscriptionID: rID.SubscriptionID,
			ResourceGroup:  rID.ResourceGroup,
			Name:           rID.Name,
			Policy:         existing.Policy,
			PolicyID:       existing.PolicyID,
		}
	default:
		// if both Original and backup are provided, then return Original with both custom and managed rules replaced
		rID := policy.ParseResourceID(existing.PolicyID)
		existing.Policy.CustomRules = backup.Policy.CustomRules
		existing.Policy.ManagedRules = backup.Policy.ManagedRules

		return policy.WrappedPolicy{
			SubscriptionID: rID.SubscriptionID,
			ResourceGroup:  rID.ResourceGroup,
			Name:           rID.Name,
			Policy:         existing.Policy,
			PolicyID:       existing.PolicyID,
		}
	}
}
