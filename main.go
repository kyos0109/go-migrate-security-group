package main

import (
	"flag"
	"os"

	"github.com/aws/aws-sdk-go/service/ec2"
)

var (
	help       bool
	sourceSGID string
)

func init() {
	flag.BoolVar(&help, "h", false, "This help")
	flag.StringVar(&sourceSGID, "sid", "", "Source Security Group ID")
	flag.Parse()

	if help {
		flag.Usage()
		os.Exit(1)
	}
}

// AWSSync ...
type AWSSync struct {
	sourceSGLists []*ec2.SecurityGroup
	perfixListMap map[string]*PerfixList
}

func main() {
	var awssync AWSSync

	awssync.perfixListMap = make(map[string]*PerfixList)

	yamlConfig := GetConfig("config.yaml")

	if len(sourceSGID) > 0 {
		awssync.sourceSGLists = GetFilterSGListByIds(&yamlConfig.Setting.Source, sourceSGID)
		awssync.GetPerfixLists(&yamlConfig.Setting.Source)
	} else {
		awssync.sourceSGLists = GetSGList(&yamlConfig.Setting.Source)
		awssync.GetPerfixLists(&yamlConfig.Setting.Source)
	}

	awssync.CreateAndSyncSGList(&yamlConfig.Setting.Destination, &yamlConfig.Setting.DryRun)
}
