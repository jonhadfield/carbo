package carbo

import (
	"fmt"
	"log"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/frontdoor/mgmt/frontdoor"
)

func deleteCustomRules(s *session, dcri DeleteCustomRulesInput) (err error) {
	var p frontdoor.WebApplicationFirewallPolicy

	subscription := dcri.RID.SubscriptionID
	resourceGroup := dcri.RID.ResourceGroup
	name := dcri.RID.Name

	// check if Policy exists
	p, err = s.getRawPolicy(subscription, resourceGroup, name)
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

	err = s.pushPolicy(pushPolicyInput{
		Name:          *p.Name,
		subscription:  dcri.RID.SubscriptionID,
		resourceGroup: dcri.RID.ResourceGroup,
		policy:        p,
		Debug:         dcri.Debug,
	})

	return err
}
