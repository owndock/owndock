package agentprotocol

// Version is the only wire protocol implemented by both the Agent and Server.
// A new value requires parallel decoders/encoders and a mixed-version release
// matrix; configuration alone must never claim support for an unimplemented
// protocol.
const Version = "v1"
