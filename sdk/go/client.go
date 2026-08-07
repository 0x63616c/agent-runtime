package agentruntime

import "context"

// Client is the Temporal-free application contract for durable Agent Runtime commands.
//
// Implementations may use HTTP, but durable work never depends on the lifetime
// of a caller connection or context after a mutation has been accepted.
type Client interface {
	CreateAgent(context.Context, CreateAgentRequest) (AgentSpecification, error)
	ReviseAgent(context.Context, ReviseAgentRequest) (AgentSpecification, error)
	CreateSession(context.Context, CreateSessionRequest) (Session, error)
	SendInput(context.Context, SendInputRequest) (SendInputResult, error)
	InspectSession(context.Context, SessionID) (SessionView, error)
	Events(context.Context, SessionID, Cursor, int) (EventPage, error)
	CancelTurn(context.Context, CancelTurnRequest) (Turn, error)
	CloseSession(context.Context, CloseSessionRequest) (Session, error)
}
