package goexporter

import "strings"

func ClassifyActorType(comm string) string {
	if strings.HasPrefix(comm, "ptlrpcd_") {
		return "client_worker"
	}
	for _, prefix := range BatchJobPrefixes {
		if strings.HasPrefix(comm, prefix) {
			return "batch_job"
		}
	}
	if _, ok := DaemonNames[comm]; ok || strings.HasSuffix(comm, "exporter") {
		return "system_daemon"
	}
	return "user"
}

func AccessIntentForOp(op string) string {
	if intent, ok := IntentForOp[op]; ok {
		return intent
	}
	return ""
}
