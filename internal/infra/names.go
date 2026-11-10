package infra

// The names the agent leaves on a host and in its messages, in one place:
// directories, the download cache, the binary, the metrics and their
// textfile, temporary files and the deploy key's title all derive from them.
const (
	// agentName names the directories (/etc/<name>, /var/lib/<name>), the
	// temporary files and the deploy key's title.
	agentName = "infrafier"
	// metricPrefix starts every metric pull writes, and the textfile's name.
	metricPrefix = "infrafier"
	// binaryName is the binary in /usr/local/bin and in bootstrap's upload.
	binaryName = "infrafier"
	// agentCommand is how messages tell the operator what to run.
	agentCommand = binaryName
)

// The same names for the CLI (the main package), and the ones only it uses.
const (
	AgentName    = agentName
	BinaryName   = binaryName
	AgentCommand = agentCommand
	// PullTimer runs pull on a host. The desired-state repo installs it,
	// usually from a module of its own; the package itself never names it.
	PullTimer = agentName + "-pull.timer"
	// OperatorIdentityEnv overrides where the operator's age identity is
	// (DefaultOperatorIdentity).
	OperatorIdentityEnv = "INFRAFIER_AGE_IDENTITY"
)
