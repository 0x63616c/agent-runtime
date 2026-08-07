package agentruntime

import "fmt"

// Error is a safe runtime-owned command failure suitable for errors.As.
type Error struct {
	Failure Failure
}

// Error returns only the stable code and safe bounded message.
func (runtimeError *Error) Error() string {
	if runtimeError == nil {
		return "agent runtime error"
	}
	return fmt.Sprintf("%s: %s", runtimeError.Failure.Code, runtimeError.Failure.Message)
}
