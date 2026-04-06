package goexporter

import "strings"

func ClassifyActorType(comm string) string {
	if strings.HasPrefix(comm, "ptlrpcd_") {
		return ActorClientWorker
	}
	for _, prefix := range BatchJobPrefixes {
		if strings.HasPrefix(comm, prefix) {
			return ActorBatchJob
		}
	}
	if _, ok := DaemonNames[comm]; ok || strings.HasSuffix(comm, "exporter") {
		return ActorSystemDaemon
	}
	return ActorUser
}

func AccessIntentForOp(op string) string {
	if intent, ok := IntentForOp[op]; ok {
		return intent
	}
	return ""
}
