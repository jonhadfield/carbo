package carbo

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/storage/mgmt/storage"
	"github.com/Azure/azure-storage-blob-go/azblob"
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
	s := session{}

	// fail if only one of the storage account destination required parameters been defined
	if (i.StorageAccountResourceID != "" && i.ContainerURL == "") || (i.StorageAccountResourceID == "" && i.ContainerURL != "")  {
		return fmt.Errorf("both storage account resource id and container url are required for backups to Azure Storage")
	}

	// fail if neither path nor storage account details are provided
	if i.StorageAccountResourceID == "" && i.Path == "" {
		return fmt.Errorf("either path or storage account details are required")
	}

	if len(i.RIDs) == 0 && i.SubscriptionID == "" {
		return fmt.Errorf("either subscription id or resource ids are required")
	}

	o, err := s.getWrappedPolicies(getWrappedPoliciesInput{
		subscriptionID:    i.SubscriptionID,
		appVersion:        i.AppVersion,
		filterResourceIDs: i.RIDs,
	})
	if err != nil {
		return err
	}

	logrus.Debugf("retrieved %d policies", len(o.policies))

	var containerURL azblob.ContainerURL
	if i.StorageAccountResourceID != "" {
		sari := ParseResourceID(i.StorageAccountResourceID)
		storageAccountsClient := storage.NewAccountsClient(sari.SubscriptionID)
		storageAccountsClient.Authorizer = *s.authorizer
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

	return backupPolicies(o.policies, containerURL, i.FailFast, i.Quiet, i.Path)
}

// backupPolicy takes a WrappedPolicy as input and creates a json file that can later be restored
func backupPolicy(policy WrappedPolicy, containerURL azblob.ContainerURL, failFast, quiet bool, path string) (err error) {
	t := time.Now().UTC().Format("20060102150405")

	var cwd string

	if !quiet {
		cwd, err = os.Getwd()
		if err != nil {
			return
		}

		msg := fmt.Sprintf("backing up Policy: %s", policy.Name)
		statusOutput := PadToWidth(msg, " ", 0, true)
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
		if ! quiet {
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
func backupPolicies(policies []WrappedPolicy, containerURL azblob.ContainerURL, failFast, quiet bool, path string) (err error) {
	for _, p := range policies {
		err = backupPolicy(p, containerURL, failFast, quiet, path)

		if failFast {
			return
		}
	}

	return
}
