package policy

import (
	"context"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/frontdoor/mgmt/frontdoor"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/jonhadfield/carbo/helpers"
	"github.com/sirupsen/logrus"
	"github.com/ztrue/tracerr"
	"time"
)

type Session struct {
	Authorizer               *autorest.Authorizer
	FrontDoorPoliciesClients map[string]*frontdoor.PoliciesClient
	FrontDoorsClients        map[string]*frontdoor.FrontDoorsClient
	ResourcesClients         map[string]*resources.Client
}

func (s *Session) GetAuthorizer() error {
	if s.Authorizer != nil {
		return nil
	}
	// try from environment first
	a, err := auth.NewAuthorizerFromEnvironment()
	if err == nil {
		s.Authorizer = &a

		logrus.Debug("retrieved Authorizer from environment")

		return nil
	}

	a, err = auth.NewAuthorizerFromCLI()
	if err == nil {
		s.Authorizer = &a

		logrus.Debug("retrieved Authorizer from cli")

		return nil
	}

	return err
}

func (s *Session) GetRawPolicy(subscription string, resourceGroup string, name string) (wafPolicy frontdoor.WebApplicationFirewallPolicy, err error) {
	err = s.getFrontDoorPoliciesClient(subscription)
	if err != nil {
		return
	}

	logrus.Debugf("requesting AFD Policy with: %s %s %s", subscription, resourceGroup, name)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	wafPolicy, err = s.FrontDoorPoliciesClients[subscription].Get(ctx, resourceGroup, name)

	return
}

// PushPolicyInput defines the input for the PushPolicy function
type PushPolicyInput struct {
	Name          string
	Subscription  string
	ResourceGroup string
	Policy        frontdoor.WebApplicationFirewallPolicy
	Debug         bool
	Timeout       int64
	Async         bool
}

const (
	PushPolicyTimeout       = 120
	PushPolicyPollFrequency = 10
)

// PushPolicy creates or updates a waf Policy with the provided Policy instance.
func (s *Session) PushPolicy(i PushPolicyInput) (err error) {
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
		logrus.Debugf("using sync for Policy push with timeout: %s", timeout.String())

		select {
		case <-time.After(PushPolicyPollFrequency * time.Second):
			fmt.Println("Policy push in progress...")
		case <-ctx.Done():
			if err = ctx.Err(); err != nil {
				return err
			}

			return
		}
	} else {
		logrus.Debug("using async for Policy push")
		ctx = context.Background()
	}

	// check we're not missing a Policies client for the Subscription
	err = s.getFrontDoorPoliciesClient(i.Subscription)
	if err != nil {
		return
	}

	result, err := s.FrontDoorPoliciesClients[i.Subscription].CreateOrUpdate(ctx, i.ResourceGroup, i.Name, i.Policy)
	if err != nil {
		return
	}
	logrus.Debugf("Policy push result: %s", result.Status())

	if i.Async {
		fmt.Println("Policy push started asynchronously")

		return
	}

	fmt.Println("Policy successfully pushed")

	return
}

func (s *Session) GetAllPolicies(i GetWrappedPoliciesInput) (gres []resources.GenericResourceExpanded, err error) {
	err = s.getResourcesClient(i.SubscriptionID)
	if err != nil {
		return
	}

	ctx := context.Background()

	top := int32(i.Max)
	if i.Max == 0 {
		top = helpers.MaxPoliciesToFetch
	}

	logrus.Debugf("listing first %d Policies in Subscription: %s", top, i.SubscriptionID)

	it, err := s.ResourcesClients[i.SubscriptionID].ListComplete(ctx, "resourceType eq 'Microsoft.Network/frontdoorWebApplicationFirewallPolicies'", "", &top)
	if err != nil {
		return
	}

	var total int

	for it.NotDone() {
		if it.Value().ID == nil {
			return nil, tracerr.Errorf("Azure returned a WAF Policy without a resource ID: %+v", it.Value())
		}

		// add if filters not provided, or filters are provided, and we have a match
		if len(i.FilterResourceIDs) == 0 || helpers.StringInSlice(*it.Value().ID, i.FilterResourceIDs, true) {
			gres = append(gres, it.Value())
		}

		total++

		// passing top as top number of items isn't working due to an API bug
		// if we have reached top here, then return
		if total == int(top) {
			return
		}

		if err = it.NextWithContext(ctx); err != nil {
			return
		}
	}

	logrus.Debugf("retrieved %d resources", total)

	return gres, err
}

// getResourcesClient creates a new resources client instance and stores it in the provided session.
// if an Authorizer instance is missing, it will make a call to create it and then store in the session also.
func (s *Session) getResourcesClient(subID string) (err error) {
	if s.ResourcesClients == nil {
		s.ResourcesClients = make(map[string]*resources.Client)
	}

	if s.ResourcesClients[subID] != nil {
		logrus.Debugf("re-using resources client for Subscription: %s", subID)

		return nil
	}

	logrus.Debugf("creating resources client for Subscription: %s", subID)

	c := resources.NewClient(subID)

	err = s.GetAuthorizer()
	if err != nil {
		return
	}

	s.ResourcesClients[subID] = &c
	s.ResourcesClients[subID].Authorizer = *s.Authorizer

	return
}

// getFrontDoorsClient creates a front doors client for the given Subscription and stores it in the provided session.
// if an Authorizer instance is missing, it will make a call to create it and then store in the session also.
func (s *Session) GetFrontDoorsClient(subID string) (c frontdoor.FrontDoorsClient, err error) {
	if s.FrontDoorsClients == nil {
		s.FrontDoorsClients = make(map[string]*frontdoor.FrontDoorsClient)
	}

	if s.FrontDoorsClients[subID] != nil {
		logrus.Debugf("re-using front doors client for Subscription: %s", subID)

		return *s.FrontDoorsClients[subID], nil
	}

	logrus.Debugf("creating front doors client")

	frontDoorsClient := frontdoor.NewFrontDoorsClient(subID)

	err = s.GetAuthorizer()
	if err != nil {
		return
	}

	frontDoorsClient.Authorizer = *s.Authorizer

	s.FrontDoorsClients[subID] = &frontDoorsClient

	return
}

// getFrontDoorPoliciesClient creates a front doors Policies client for the given Subscription and stores it in the provided session.
// if an Authorizer instance is missing, it will make a call to create it and then store in the session also.
func (s *Session) getFrontDoorPoliciesClient(subID string) (err error) {
	if s.FrontDoorPoliciesClients == nil {
		s.FrontDoorPoliciesClients = make(map[string]*frontdoor.PoliciesClient)
	}
	if s.FrontDoorPoliciesClients[subID] != nil {
		logrus.Debugf("re-using front door Policies client for Subscription: %s", subID)

		return nil
	}

	logrus.Debugf("creating front door Policies client for Subscription: %s", subID)

	if s.Authorizer == nil {
		err = s.GetAuthorizer()
		if err != nil {
			return
		}
	}

	frontDoorPoliciesClient := frontdoor.NewPoliciesClient(subID)
	frontDoorPoliciesClient.Authorizer = *s.Authorizer
	s.FrontDoorPoliciesClients[subID] = &frontDoorPoliciesClient

	return
}

type GetWrappedPoliciesInput struct {
	SubscriptionID    string
	AppVersion        string
	FilterResourceIDs []string
	Max               int
}

type GetWrappedPoliciesOutput struct {
	Policies []WrappedPolicy
}

func (s *Session) GetWrappedPolicies(i GetWrappedPoliciesInput) (o GetWrappedPoliciesOutput, err error) {
	var rids []ResourceID

	if len(i.FilterResourceIDs) > 0 {
		// if ids to filter have been provided then simply parse as ResourceIDs
		rids = ParseResourceIDs(i.FilterResourceIDs)
	} else {
		// retrieve all Policies as generic resources
		var gres []resources.GenericResourceExpanded
		gres, err = s.GetAllPolicies(i)
		if err != nil {
			return
		}

		rids = GetResourceIDsFromGenericResources(gres)
	}

	for _, rid := range rids {
		var p frontdoor.WebApplicationFirewallPolicy
		logrus.Debugf("retrieving raw Policy with: %s %s %s", rid.SubscriptionID, rid.ResourceGroup, rid.Name)

		p, err = s.GetRawPolicy(rid.SubscriptionID, rid.ResourceGroup, rid.Name)
		if err != nil {
			return
		}

		wp := WrappedPolicy{
			Date:           time.Now().UTC(),
			SubscriptionID: rid.SubscriptionID,
			ResourceGroup:  rid.ResourceGroup,
			Name:           rid.Name,
			Policy:         p,
			PolicyID:       rid.Raw,
			AppVersion:     i.AppVersion,
		}

		o.Policies = append(o.Policies, wp)
	}

	return
}

func GetFrontDoorIDs(s *Session, subID string) (ids []string, err error) {
	// get all front door ids
	err = s.getResourcesClient(subID)
	if err != nil {
		return
	}

	ctx := context.Background()

	max := int32(helpers.MaxFrontDoorsToFetch)

	it, err := s.ResourcesClients[subID].ListComplete(ctx, "resourceType eq 'Microsoft.Network/frontdoors'", "", &max)
	if err != nil {
		return
	}

	for it.NotDone() {
		if it.Value().ID == nil {
			panic("unexpected front door with nil id returned")
		}

		ids = append(ids, *it.Value().ID)

		err = it.NextWithContext(ctx)
		if err != nil {
			return
		}
	}

	return
}

func GetFrontDoors(s *Session, subID string) (frontDoors FrontDoors, err error) {
	frontDoorIDs, err := GetFrontDoorIDs(s, subID)
	if err != nil || len(frontDoorIDs) == 0 {
		return
	}

	_, err = s.GetFrontDoorsClient(subID)
	if err != nil {
		return
	}

	err = s.getFrontDoorPoliciesClient(subID)
	if err != nil {
		return
	}

	// get all front doors by id
	for _, frontDoorID := range frontDoorIDs {
		var fd FrontDoor

		fd, err = GetFrontDoorByID(s, frontDoorID)
		if err != nil {
			return
		}

		frontDoors = append(frontDoors, FrontDoor{
			Name:      fd.Name,
			Endpoints: fd.Endpoints,
		})
	}

	return
}
