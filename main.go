package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/service/ec2"
)

var (
	help                bool
	updateMode          bool
	sourceSGID          string
	dontTouchThisButton bool
)

func init() {
	flag.BoolVar(&help, "h", false, "This help")
	flag.BoolVar(&updateMode, "u", false, "Security Group Update Mode")
	flag.BoolVar(&dontTouchThisButton, "dontTouchThisButton", false, "Clean Destination Security Group Rule, Don't Try It.")
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

func askForConfirmation(s string) bool {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Printf("%s [y/n]: ", s)

		response, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}

		response = strings.ToLower(strings.TrimSpace(response))

		if response == "y" || response == "yes" {
			return true
		} else if response == "n" || response == "no" {
			return false
		}
	}
}

func main() {
	var awssync AWSSync

	awssync.perfixListMap = make(map[string]*PerfixList)

	yamlConfig := GetConfig("config.yaml")

	switch {
	case updateMode:
		log.Printf("Update Mode: %t", updateMode)
		log.Println("Destination Security Group Will Be Revoke Rule, If Security Group ID Exist.")
		c := askForConfirmation("Do you really want to keep?")

		if !c {
			fmt.Println("Bye...")
			os.Exit(0)
		}
	case dontTouchThisButton:
		c := askForConfirmation("Doooooooooooooooooooooooooooooooooooooon't, Are You Sure?")

		if !c {
			fmt.Println("Bye...")
			os.Exit(0)
		}
		cc := askForConfirmation(fmt.Sprintf("AccessKey: %s, Sure?", yamlConfig.Setting.Destination.AccessKey))

		if !cc {
			fmt.Println("Bye...")
			os.Exit(0)
		}

		CleanDstSecurityGroupRule(&yamlConfig.Setting.Destination)
		os.Exit(0)
	}

	if len(sourceSGID) > 0 {
		awssync.sourceSGLists = GetFilterSGListByIds(&yamlConfig.Setting.Source, sourceSGID)
		awssync.GetPerfixLists(&yamlConfig.Setting.Source)
	} else {
		awssync.sourceSGLists = GetSGList(&yamlConfig.Setting.Source)
		awssync.GetPerfixLists(&yamlConfig.Setting.Source)
	}

	awssync.CreateAndSyncSGList(&yamlConfig.Setting.Destination, &yamlConfig.Setting.DryRun)
}
