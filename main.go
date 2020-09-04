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

func main() {
	yamlConfig := GetConfig("config.yaml")

	var sourceSGList []*ec2.SecurityGroup

	if len(sourceSGID) > 0 {
		sourceSGList = GetFilterSGList(&yamlConfig.Setting.Source, sourceSGID)
	} else {
		sourceSGList = GetSGList(&yamlConfig.Setting.Source)
	}

	CreateAndSyncSGList(&yamlConfig.Setting.Destination, sourceSGList, &yamlConfig.Setting.DryRun)
}
