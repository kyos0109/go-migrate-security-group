package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
)

const (
	sgSelf        = "sg-self"
	sgDefaultName = "default"
)

// BuildSGMapType ...
type BuildSGMapType map[*string][]*ec2.IpPermission

// SGIdNameMapType ...
type SGIdNameMapType map[string]string

var (
	// ID: Name
	sgIDMameMap = make(SGIdNameMapType)

	// Name: ID
	newSGNameIDMap = make(SGIdNameMapType)

	ipps  = make(BuildSGMapType)
	ippes = make(BuildSGMapType)
)

func newSVC(account *awsAuth) *ec2.EC2 {
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(account.Region),
		Credentials: credentials.NewStaticCredentials(account.AccessKey, account.SecretKey, ""),
	})
	if err != nil {
		log.Fatalf("AWS Session Error: %v", err)
	}

	return ec2.New(sess)
}

// GetFilterSGListByNames ...
func GetFilterSGListByNames(account *awsAuth, names string) []*ec2.SecurityGroup {
	svc := newSVC(account)

	result, err := svc.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		GroupNames: aws.StringSlice([]string{names}),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case "InvalidGroupName.Malformed":
				fallthrough
			case "InvalidGroup.NotFound":
				exitErrorf("%s.", aerr.Message())
			}
		}
		exitErrorf("Unable to get descriptions for security groups, %v", err)
	}

	log.Println("Successfully get security group, filter by name")
	return result.SecurityGroups
}

// GetFilterSGListByIds ...
func GetFilterSGListByIds(account *awsAuth, groupIds string) []*ec2.SecurityGroup {
	svc := newSVC(account)

	result, err := svc.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		GroupIds: aws.StringSlice([]string{groupIds}),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case "InvalidGroupId.Malformed":
				fallthrough
			case "InvalidGroup.NotFound":
				exitErrorf("%s.", aerr.Message())
			}
		}
		exitErrorf("Unable to get descriptions for security groups, %v", err)
	}

	log.Println("Successfully get security group, filter by id")
	return result.SecurityGroups
}

// GetSGList ...
func GetSGList(account *awsAuth) []*ec2.SecurityGroup {
	svc := newSVC(account)

	result, err := svc.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case "InvalidGroupId.Malformed":
				fallthrough
			case "InvalidGroup.NotFound":
				exitErrorf("%s.", aerr.Message())
			}
		}
		exitErrorf("Unable to get descriptions for security groups, %v", err)
	}

	log.Println("Successfully get security group list")
	return result.SecurityGroups
}

// PerfixList ...
type PerfixList struct {
	OldPerfixListID   *string
	newPerfixListID   *string
	ManagedPrefixList *ec2.ManagedPrefixList
	PrefixListEntry   []*ec2.PrefixListEntry
}

// GetPerfixLists ...
func (awssync *AWSSync) GetPerfixLists(account *awsAuth) {
	svc := newSVC(account)

	for _, sg := range awssync.sourceSGLists {
		for _, ipp := range sg.IpPermissions {
			for _, plids := range ipp.PrefixListIds {
				p := new(PerfixList)
				p.OldPerfixListID = plids.PrefixListId
				result, err := svc.GetManagedPrefixListEntries(&ec2.GetManagedPrefixListEntriesInput{
					PrefixListId: p.OldPerfixListID,
				})
				if err != nil {
					log.Println("Get PerfixList Error", err)
				}

				p.PrefixListEntry = result.Entries

				perfixListInfo, err := svc.DescribeManagedPrefixLists(&ec2.DescribeManagedPrefixListsInput{
					PrefixListIds: aws.StringSlice([]string{*p.OldPerfixListID}),
				})
				if err != nil {
					log.Println("Describe Perfix Error", err)
				}

				p.ManagedPrefixList = perfixListInfo.PrefixLists[0]

				awssync.perfixListMap[*p.OldPerfixListID] = p

				log.Println("Found PerfixList, Add To Sync Data")
				return
			}
		}
	}
	return
}

func (awssync *AWSSync) createPerfixList(svc *ec2.EC2) {
	for i, v := range awssync.perfixListMap {
		PerfixListAddr := convertAddPerfixList(v.PrefixListEntry)
		tags := []*ec2.Tag{}

		result, err := svc.CreateManagedPrefixList(&ec2.CreateManagedPrefixListInput{
			AddressFamily:     v.ManagedPrefixList.AddressFamily,
			Entries:           PerfixListAddr,
			PrefixListName:    v.ManagedPrefixList.PrefixListName,
			MaxEntries:        v.ManagedPrefixList.MaxEntries,
			TagSpecifications: setSGTags(tags, "prefix-list"),
		})
		if err != nil {
			log.Println("Create PerfixList Error", err)
		}

		awssync.perfixListMap[i].newPerfixListID = result.PrefixList.PrefixListId
	}
}

func convertAddPerfixList(plist []*ec2.PrefixListEntry) []*ec2.AddPrefixListEntry {
	var newPlist []*ec2.AddPrefixListEntry

	for _, v := range plist {

		pAddr := &ec2.AddPrefixListEntry{
			Cidr:        v.Cidr,
			Description: v.Description,
		}

		newPlist = append(newPlist, pAddr)
	}
	return newPlist
}

func deletSGDefaultValue(sgList []*ec2.SecurityGroup) []*ec2.SecurityGroup {
	// delete non vpc id default sg from source
	for i, sg := range sgList {
		if aws.StringValue(sg.GroupName) == "default" && aws.StringValue(sg.VpcId) == "" {
			log.Printf("This Source Security Group: %v(%v), Not Found VPC ID, Ignore SYNC.", *sg.GroupName, *sg.GroupId)
			copy(sgList[i:], sgList[i+1:])
			sgList[len(sgList)-1] = &ec2.SecurityGroup{}
			sgList = sgList[:len(sgList)-1]
		}
	}

	// delete sg egress default 0.0.0.0/0
	for _, sg := range sgList {
		for ii, ipp := range sg.IpPermissionsEgress {
			for _, ipr := range ipp.IpRanges {
				if aws.StringValue(ipr.CidrIp) == "0.0.0.0/0" && aws.StringValue(ipp.IpProtocol) == "-1" {
					copy(sg.IpPermissionsEgress[ii:], sg.IpPermissionsEgress[ii+1:])
					sg.IpPermissionsEgress[len(sg.IpPermissionsEgress)-1] = &ec2.IpPermission{}
					sg.IpPermissionsEgress = sg.IpPermissionsEgress[:len(sg.IpPermissionsEgress)-1]
				}
			}
		}
	}

	// delete Security Group include Security Group ID, and copy to new map.
	for _, sg := range sgList {
		for ii, ipp := range sg.IpPermissions {
			for range ipp.UserIdGroupPairs {
				if aws.StringValue(sg.GroupName) == sgDefaultName {
					sg.IpPermissions[ii] = nil
					break
				}
				ipps[sg.GroupId] = append(ippes[sg.GroupId], sg.IpPermissions[ii])
				sg.IpPermissions[ii] = nil
				break
			}
		}
	}

	// clean empty IpPermissions
	// for _, sg := range sgList {
	// 	for ii, ipp := range sg.IpPermissions {
	// 		if len(ipp.IpRanges) <= 0 {
	// 			fmt.Println(len(sg.IpPermissions))
	// 			sg.IpPermissions = append(sg.IpPermissions[:ii], sg.IpPermissions[ii+1:]...)
	// 		}
	// 	}
	// }

	// delete Security Group include Security Group ID, and copy to new map.
	for _, sg := range sgList {
		for ii, ipp := range sg.IpPermissionsEgress {
			for range ipp.UserIdGroupPairs {
				if aws.StringValue(sg.GroupName) == sgDefaultName {
					sg.IpPermissionsEgress[ii] = nil
					break
				}
				ippes[sg.GroupId] = append(ippes[sg.GroupId], sg.IpPermissionsEgress[ii])
				sg.IpPermissionsEgress[ii] = nil
				break
			}
		}
	}

	// // clean empty IpPermissionsEgress
	// for _, sg := range sgList {
	// 	for ii, ipp := range sg.IpPermissionsEgress {
	// 		if len(ipp.IpRanges) <= 0 {
	// 			sg.IpPermissionsEgress = append(sg.IpPermissionsEgress[:ii], sg.IpPermissionsEgress[ii+1:]...)
	// 		}
	// 	}
	// }

	return sgList
}

func replaceGroupID(ippMap BuildSGMapType) BuildSGMapType {
	newBuildSG := make(BuildSGMapType)

	for gid, data := range ippMap {
		gName, ok := sgIDMameMap[aws.StringValue(gid)]
		if !ok {
			log.Println("Not Found Old Security Group ID In Map, ID:", *gid)
			break
		}

		newGID, ok := newSGNameIDMap[gName]
		if !ok {
			log.Println("Not Found New Security Group Name In Map, Name:", gName)
			break
		}

		newBuildSG[aws.String(newGID)] = data
	}

	for _, ipp := range newBuildSG {
		for _, ips := range ipp {
			for _, ugp := range ips.UserIdGroupPairs {
				gName, ok := sgIDMameMap[aws.StringValue(ugp.GroupId)]
				if !ok {
					log.Println("Not Found Old Security Group ID In Map, From UserIdGroupPairs, ID:", *ugp.GroupId)
					break
				}

				newID, ok := newSGNameIDMap[gName]
				if !ok {
					log.Println("Not Found New Security Group Name In Map, From UserIdGroupPairs, Name:", gName)
					break
				}

				ugp.GroupId = aws.String(newID)
			}
		}
	}

	return newBuildSG
}

func (awssync *AWSSync) replacePerfixListID(sgList []*ec2.SecurityGroup) []*ec2.SecurityGroup {
	for _, sg := range sgList {
		for _, ipp := range sg.IpPermissions {
			if ipp != nil {
				for _, plist := range ipp.PrefixListIds {
					plist.PrefixListId = awssync.perfixListMap[*plist.PrefixListId].newPerfixListID
				}
			}
		}
	}
	return sgList
}

func setSGTags(tags []*ec2.Tag, resourceType string) []*ec2.TagSpecification {
	tagList := &ec2.TagSpecification{}
	timeTag := &ec2.Tag{}

	timeTag.Key = aws.String("CreateAt")
	timeTag.Value = aws.String(time.Now().String())

	tags = append(tags, timeTag)

	if len(tags) > 0 {
		tagList = &ec2.TagSpecification{
			Tags:         tags,
			ResourceType: aws.String(resourceType),
		}
	}
	return []*ec2.TagSpecification{tagList}
}

// CreateAndSyncSGList ...
func (awssync *AWSSync) CreateAndSyncSGList(account *awsAuth, dryRun *bool) {
	svc := newSVC(account)

	defaultSGID := deletSGDefaultValue(GetFilterSGListByNames(account, sgDefaultName))[0]

	newSGList := deletSGDefaultValue(awssync.sourceSGLists)

	awssync.createPerfixList(svc)

	newSGList = awssync.replacePerfixListID(newSGList)

	for _, sg := range newSGList {
		sgIDMameMap[*sg.GroupId] = *sg.GroupName

		createRes, err := svc.CreateSecurityGroup(&ec2.CreateSecurityGroupInput{
			DryRun:            dryRun,
			GroupName:         sg.GroupName,
			Description:       sg.Description,
			VpcId:             aws.String(account.VIPCID),
			TagSpecifications: setSGTags(sg.Tags, ec2.ResourceTypeSecurityGroup),
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case "InvalidVpcID.NotFound":
					exitErrorf("Unable to find VPC with ID %q.", account.VIPCID)
				case "InvalidGroup.Duplicate":
					exitErrorf("Security group %q already exists.", *sg.GroupName)
				case "DryRunOperation":
					exitErrorf("DryRunOperation to create security group %q, %v", *sg.GroupName, err)
				case "InvalidParameterValue":
					if aws.StringValue(sg.GroupName) == sgDefaultName {
						log.Print("Found default group, switch id.")
						createRes.GroupId = defaultSGID.GroupId
						break
					}
					exitErrorf("InvalidParameterValue to create security group %q, %v", *sg.GroupName, err)
				default:
					exitErrorf("Unable to create security group %q, %v", *sg.GroupName, err)
				}
			}
		}

		// all new security group id
		newSGNameIDMap[*sg.GroupName] = *createRes.GroupId

		log.Printf("Created security group %s(%s) with VPC %s.\n",
			aws.StringValue(sg.GroupName), aws.StringValue(createRes.GroupId), account.VIPCID)

		if len(sg.IpPermissions) > 0 && sg.IpPermissions[0] != nil {
			_, err = svc.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
				GroupId:       createRes.GroupId,
				IpPermissions: setSelfSecurityGroupID(sg.IpPermissions, createRes.GroupId),
			})
			if err != nil {
				exitErrorf("Unable to set security group %q ingress, %v", *sg.GroupName, err)
			}
		}

		if len(sg.IpPermissionsEgress) > 0 && sg.IpPermissionsEgress[0] != nil {
			_, err = svc.AuthorizeSecurityGroupEgress(&ec2.AuthorizeSecurityGroupEgressInput{
				GroupId:       createRes.GroupId,
				IpPermissions: setSelfSecurityGroupID(sg.IpPermissionsEgress, createRes.GroupId),
			})
			if err != nil {
				exitErrorf("Unable to set security group %q Egress, %v", *sg.GroupName, err)
			}
		}
	}

	if len(ipps) > 0 {
		newUgpMap := replaceGroupID(ipps)

		for gid, ipps := range newUgpMap {
			_, err := svc.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
				GroupId:       gid,
				IpPermissions: ipps,
			})
			if err != nil {
				exitErrorf("Unable to set security group %q ingress, %v", *gid, err)
			}
		}

	}

	if len(ippes) > 0 {
		newUgpMap := replaceGroupID(ippes)

		for gid, ipps := range newUgpMap {
			_, err := svc.AuthorizeSecurityGroupEgress(&ec2.AuthorizeSecurityGroupEgressInput{
				GroupId:       gid,
				IpPermissions: ipps,
			})
			if err != nil {
				exitErrorf("Unable to set security group %q Egress, %v", *gid, err)
			}
		}
	}

	log.Println("Successfully set security group ingress")
}

func setSelfSecurityGroupID(ips []*ec2.IpPermission, groupID *string) []*ec2.IpPermission {
	for _, ipp := range ips {
		if ipp != nil {
			for _, ugp := range ipp.UserIdGroupPairs {
				if aws.StringValue(ugp.GroupId) == sgSelf {
					ugp.GroupId = groupID
				}
			}
		}
	}
	return ips
}

func exitErrorf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}
