package main

import (
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
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

// GetFilterSGList ...
func GetFilterSGList(account *awsAuth, groupIds string) []*ec2.SecurityGroup {
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

	log.Println("Successfully get security group: ", len(result.SecurityGroups))
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

func deletSGDefaultValue(sgList []*ec2.SecurityGroup) []*ec2.SecurityGroup {
	// delete default sg from source
	for i, sg := range sgList {
		if aws.StringValue(sg.GroupName) == "default" {
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

	// delete sg include sg id
	for _, sg := range sgList {
		for ii, ipp := range sg.IpPermissions {
			for range ipp.UserIdGroupPairs {
				copy(sg.IpPermissions[ii:], sg.IpPermissions[ii+1:])
				sg.IpPermissions[len(sg.IpPermissions)-1] = &ec2.IpPermission{}
				sg.IpPermissions = sg.IpPermissions[:len(sg.IpPermissions)-1]
			}
		}
	}

	return sgList
}

// CreateAndSyncSGList ...
func CreateAndSyncSGList(account *awsAuth, sgList []*ec2.SecurityGroup, dryRun *bool) {
	svc := newSVC(account)

	newSGList := deletSGDefaultValue(sgList)

	for _, sg := range newSGList {
		createRes, err := svc.CreateSecurityGroup(&ec2.CreateSecurityGroupInput{
			DryRun:      dryRun,
			GroupName:   aws.String(*sg.GroupName),
			Description: aws.String(*sg.Description),
			VpcId:       aws.String(account.VIPCID),
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
				default:
					exitErrorf("Unable to create security group %q, %v", *sg.GroupName, err)
				}
			}
		}

		log.Printf("Created security group %s(%s) with VPC %s.\n",
			aws.StringValue(sg.GroupName), aws.StringValue(createRes.GroupId), account.VIPCID)

		_, err = svc.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
			GroupId:       aws.String(*createRes.GroupId),
			IpPermissions: sg.IpPermissions,
		})
		if err != nil {
			exitErrorf("Unable to set security group %q ingress, %v", *sg.GroupName, err)
		}

		if len(sg.IpPermissionsEgress) > 0 {
			_, err = svc.AuthorizeSecurityGroupEgress(&ec2.AuthorizeSecurityGroupEgressInput{

				GroupId:       aws.String(*createRes.GroupId),
				IpPermissions: sg.IpPermissionsEgress,
			})
			if err != nil {
				exitErrorf("Unable to set security group %q ingress, %v", *sg.GroupName, err)
			}
		}
	}
	log.Println("Successfully set security group ingress")
}

// FindEC2TagName ...
func FindEC2TagName(tags []*ec2.Tag) *string {
	for i, v := range tags {
		if *v.Key == "Name" {
			return tags[i].Value
		}
	}
	log.Println("Not Found Tag Name, Other Tags: ", tags)
	return nil
}

func exitErrorf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}
