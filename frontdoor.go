package carbo

import (
	"context"
	"fmt"
)

func ListFrontDoors(subID string) error {
	s := session{}

	frontDoors, err := s.getFrontDoors(subID)
	if err != nil {
		return err
	}

	if len(frontDoors) == 0 {
		fmt.Println("no front doors found")

		return nil
	}

	showFrontDoors(frontDoors)

	return nil
}

func (s *session) getFrontDoorIDs(subID string) (ids []string, err error) {
	// get all front door ids
	err = s.getResourcesClient(subID)
	if err != nil {
		return
	}

	ctx := context.Background()

	max := int32(MaxFrontDoorsToFetch)

	it, err := s.resourcesClients[subID].ListComplete(ctx, "resourceType eq 'Microsoft.Network/frontdoors'", "", &max)
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

func (s *session) getFrontDoors(subID string) (frontDoors FrontDoors, err error) {
	frontDoorIDs, err := s.getFrontDoorIDs(subID)
	if err != nil || len(frontDoorIDs) == 0 {
		return
	}

	_, err = s.getFrontDoorsClient(subID)
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

		fd, err = getFrontDoorByID(s, frontDoorID)
		if err != nil {
			return
		}

		frontDoors = append(frontDoors, FrontDoor{
			name:      fd.name,
			endpoints: fd.endpoints,
		})
	}

	return
}
