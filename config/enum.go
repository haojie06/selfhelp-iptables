package config

type DenyActionType string

const (
	DenyActionDefault DenyActionType = ""
	DenyActionReject  DenyActionType = "REJECT"
	DenyActionDrop    DenyActionType = "DROP"
)
