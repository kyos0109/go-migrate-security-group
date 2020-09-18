### This repository is archive, Please visit to https://github.com/kyos0109/go-aws-migrate

# go-migrate-security-group

The command copies the aws security group to another aws account.

Support Security Groups Include Security Group ID.

Support Security Groups Include Managed prefix lists.

Support Update(Revoke) Sync Security Groups.

example config.yaml
```yaml
Setting:
  DryRun: false
  Source:
    AccessKey: "AccessKey"
    SecretKey: "SecretKey"
    Region: "ap-southeast-1"
    VPCID: "VPCID"
  Destination:
    AccessKey: "AccessKey"
    SecretKey: "SecretKey"
    Region: "ap-east-1"
    VPCID: "VPCID"
```
