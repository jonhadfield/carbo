package session

import (
	"github.com/Azure/azure-sdk-for-go/profiles/latest/frontdoor/mgmt/frontdoor"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/sirupsen/logrus"
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

// getResourcesClient creates a new resources client instance and stores it in the provided session.
// if an Authorizer instance is missing, it will make a call to create it and then store in the session also.
func (s *Session) GetResourcesClient(subID string) (err error) {
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
func (s *Session) GetFrontDoorPoliciesClient(subID string) (err error) {
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
