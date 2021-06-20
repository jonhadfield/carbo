package carbo

import (
	"github.com/Azure/azure-sdk-for-go/profiles/latest/frontdoor/mgmt/frontdoor"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/sirupsen/logrus"
)

// getResourcesClient creates a new resources client instance and stores it in the provided session.
// if an authorizer instance is missing, it will make a call to create it and then store in the session also.
func (s *session) getResourcesClient(subID string) (err error) {
	if s.resourcesClients == nil {
		s.resourcesClients = make(map[string]*resources.Client)
	}

	if s.resourcesClients[subID] != nil {
		logrus.Debugf("re-using resources client for subscription: %s", subID)

		return nil
	}

	logrus.Debugf("creating resources client for subscription: %s", subID)

	c := resources.NewClient(subID)

	err = s.getAuthorizer()
	if err != nil {
		return
	}

	s.resourcesClients[subID] = &c
	s.resourcesClients[subID].Authorizer = *s.authorizer

	return
}

// getFrontDoorsClient creates a front doors client for the given subscription and stores it in the provided session.
// if an authorizer instance is missing, it will make a call to create it and then store in the session also.
func (s *session) getFrontDoorsClient(subID string) (c frontdoor.FrontDoorsClient, err error) {
	if s.frontDoorsClients == nil {
		s.frontDoorsClients = make(map[string]*frontdoor.FrontDoorsClient)
	}

	if s.frontDoorsClients[subID] != nil {
		logrus.Debugf("re-using front doors client for subscription: %s", subID)

		return *s.frontDoorsClients[subID], nil
	}

	logrus.Debugf("creating front doors client")

	frontDoorsClient := frontdoor.NewFrontDoorsClient(subID)

	err = s.getAuthorizer()
	if err != nil {
		return
	}

	frontDoorsClient.Authorizer = *s.authorizer

	s.frontDoorsClients[subID] = &frontDoorsClient

	return
}

// getFrontDoorPoliciesClient creates a front doors policies client for the given subscription and stores it in the provided session.
// if an authorizer instance is missing, it will make a call to create it and then store in the session also.
func (s *session) getFrontDoorPoliciesClient(subID string) (err error) {
	if s.frontDoorPoliciesClients == nil {
		s.frontDoorPoliciesClients = make(map[string]*frontdoor.PoliciesClient)
	}
	if s.frontDoorPoliciesClients[subID] != nil {
		logrus.Debugf("re-using front door policies client for subscription: %s", subID)

		return nil
	}

	logrus.Debugf("creating front door policies client for subscription: %s", subID)

	if s.authorizer == nil {
		err = s.getAuthorizer()
		if err != nil {
			return
		}
	}

	frontDoorPoliciesClient := frontdoor.NewPoliciesClient(subID)
	frontDoorPoliciesClient.Authorizer = *s.authorizer
	s.frontDoorPoliciesClients[subID] = &frontDoorPoliciesClient

	return
}

