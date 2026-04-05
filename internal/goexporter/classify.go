package goexporter

import "strings"

func ClassifyActorType(comm string) string {
	if strings.HasPrefix(comm, "ptlrpcd_") {
		return "worker"
	}
	if _, ok := DaemonNames[comm]; ok || strings.HasSuffix(comm, "exporter") {
		return "daemon"
	}
	return "user"
}

func AccessClassForOp(op string) string {
	if _, ok := LLiteMetadataOps[op]; ok {
		return "metadata"
	}
	if _, ok := LLiteDataOps[op]; ok {
		return "data"
	}
	return ""
}
