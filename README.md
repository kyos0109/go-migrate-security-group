# go-migrate-security-group

The command copies the aws security group to another aws account.

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
