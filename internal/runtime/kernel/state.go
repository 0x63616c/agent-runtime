package kernel

import agentruntime "github.com/0x63616c/agent-runtime/sdk/go"

type idempotencyRecord struct {
	command  string
	digest   string
	agent    agentruntime.AgentID
	revision agentruntime.AgentRevisionID
	session  agentruntime.SessionID
	input    agentruntime.InputID
	turn     agentruntime.TurnID
}

type agentRecord struct {
	id        agentruntime.AgentID
	revisions []agentruntime.AgentSpecification
}

type sessionRecord struct {
	session agentruntime.Session
	inputs  map[agentruntime.InputID]agentruntime.Input
	turns   []agentruntime.Turn
	events  []agentruntime.Event
	trimmed map[agentruntime.Cursor]struct{}
}

// TenantState is the kernel-owned aggregate passed only through the Repository transaction port.
//
// Persistence adapters treat this type as opaque transition state and must not
// implement domain decisions outside Kernel.
type TenantState struct {
	agents      map[agentruntime.AgentID]agentRecord
	revisions   map[agentruntime.AgentRevisionID]agentruntime.AgentSpecification
	sessions    map[agentruntime.SessionID]sessionRecord
	idempotency map[string]idempotencyRecord
}

func newTenantState() *TenantState {
	return &TenantState{
		agents:      make(map[agentruntime.AgentID]agentRecord),
		revisions:   make(map[agentruntime.AgentRevisionID]agentruntime.AgentSpecification),
		sessions:    make(map[agentruntime.SessionID]sessionRecord),
		idempotency: make(map[string]idempotencyRecord),
	}
}

func (state *TenantState) clone() *TenantState {
	if state == nil {
		return newTenantState()
	}
	clone := newTenantState()
	for id, agent := range state.agents {
		revisions := make([]agentruntime.AgentSpecification, len(agent.revisions))
		for index := range agent.revisions {
			revisions[index] = agent.revisions[index].Clone()
		}
		clone.agents[id] = agentRecord{id: agent.id, revisions: revisions}
	}
	for id, revision := range state.revisions {
		clone.revisions[id] = revision.Clone()
	}
	for id, session := range state.sessions {
		clone.sessions[id] = session.clone()
	}
	for key, record := range state.idempotency {
		clone.idempotency[key] = record
	}
	return clone
}

func (record sessionRecord) clone() sessionRecord {
	clone := sessionRecord{
		session: record.session,
		inputs:  make(map[agentruntime.InputID]agentruntime.Input, len(record.inputs)),
		turns:   make([]agentruntime.Turn, len(record.turns)),
		events:  append([]agentruntime.Event(nil), record.events...),
		trimmed: make(map[agentruntime.Cursor]struct{}, len(record.trimmed)),
	}
	for id, input := range record.inputs {
		clone.inputs[id] = input.Clone()
	}
	for index := range record.turns {
		clone.turns[index] = record.turns[index].Clone()
	}
	for cursor := range record.trimmed {
		clone.trimmed[cursor] = struct{}{}
	}
	return clone
}
