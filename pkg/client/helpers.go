package client

import (
	"fmt"
)

// checkAPIResponseStatus checks if an API response has an error status and returns an appropriate error.
// This is a helper function to reduce code duplication across API response handling.
func checkAPIResponseStatus(apiResp *APIResponse) error {
	if apiResp.Status != 0 {
		if apiResp.Error != nil {
			return fmt.Errorf("baton-oracle-fccs: API error %s: %s", apiResp.Error.ErrorCode, apiResp.Error.ErrorMessage)
		}
		return fmt.Errorf("baton-oracle-fccs: API returned status %d", apiResp.Status)
	}
	return nil
}
