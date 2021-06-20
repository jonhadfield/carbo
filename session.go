package carbo

import (
	"github.com/Azure/azure-sdk-for-go/profiles/latest/frontdoor/mgmt/frontdoor"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/sirupsen/logrus"
)

type session struct {
	authorizer               *autorest.Authorizer
	frontDoorPoliciesClients map[string]*frontdoor.PoliciesClient
	frontDoorsClients        map[string]*frontdoor.FrontDoorsClient
	resourcesClients         map[string]*resources.Client
}

func (s *session) getAuthorizer() error {
	if s.authorizer != nil {
		return nil
	}
	// try from environment first
	a, err := auth.NewAuthorizerFromEnvironment()
	if err == nil {
		s.authorizer = &a

		logrus.Debug("retrieved authorizer from environment")

		return nil
	}

	a, err = auth.NewAuthorizerFromCLI()
	if err == nil {
		s.authorizer = &a

		logrus.Debug("retrieved authorizer from cli")

		return nil
	}

	return err
}
