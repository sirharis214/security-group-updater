# update-security-group-rule

Request event will include parameters cidr_block and tag_key. Lambda will search all regions it has access to for SG's that have a tag where the Key = tag_key. Then it will check if the SG already has an ingress rule where the source IP is the provided cidr_block and the from:to ports match the value of the tag key. When a matched SG does not have a ingress rule where the source is the provided cidr_block **or** when the ingress rule's source is the cidr_block but the from:to ports aren't what they should be, then the Lambda will create a ingress rule with the required from:to ports for the provided cidr_block.

The return for this request is a map. The key of the map is the region that was searched. Value of the key is a list of dictionaries that matched the condition where tag Key = tag_key. 

* Dictionary will have a key `"message"` if SG matched the condition tag_key but no ingress rule needed to be created.
* Dictionary will have keys `"rule"`, `"status"` and `"response"` if SG matched the condition tag_key and an ingress rule was created.

Basic response syntax can be found in this [Response](#request--no-errors) section.

# Response

## Request | no errors

Request event
```python
event = {
    "type"         : "update_security_group_rule",
    "tag_key"      : "test_whitelist",
    "cidr_block"   : "10.0.0.2/32"
}
```

Request response
```python
{
    "us-east-1": [
        {
            "message": "SG sg-0931bff5d7a180d5a already had rules for this cidr:port-range combo"
        },
        {
            "rule": {
                "sg_id": "sg-0eec40bafd5628a81",
                "region": "us-east-1",
                "cidr_block": "10.0.0.2/32",
                "from_port": "443",
                "to_port": "443"
            },
            "status": "success",
            "response": {
                "Return": true,
                "SecurityGroupRules": [
                    {
                        "SecurityGroupRuleId": "sgr-056c68f4eb30b068d",
                        "GroupId": "sg-0eec40bafd5628a81",
                        "GroupOwnerId": "594924424566",
                        "IsEgress": false,
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "CidrIpv4": "10.0.0.2/32",
                        "Description": "test_whitelist created by haris/sg-updater",
                        "Tags": [
                            {
                                "Key": "Created_By",
                                "Value": "haris/sg_updater"
                            }
                        ]
                    }
                ],
                "ResponseMetadata": {
                    "RequestId": "06ea101f-01d7-4cd7-88bc-984f45b80b69",
                    "HTTPStatusCode": 200,
                    "HTTPHeaders": {
                        "x-amzn-requestid": "06ea101f-01d7-4cd7-88bc-984f45b80b69",
                        "cache-control": "no-cache, no-store",
                        "strict-transport-security": "max-age=31536000; includeSubDomains",
                        "content-type": "text/xml;charset=UTF-8",
                        "content-length": "989",
                        "date": "Mon, 20 Nov 2023 19:50:45 GMT",
                        "server": "AmazonEC2"
                    },
                    "RetryAttempts": 0
                }
            }
        }
    ],
    "us-west-1": [
        {
            "rule": {
                "sg_id": "sg-002fc945e5ffc935f",
                ...
            },
            "status": "success",
            "response": {
                "Return": true,
                "SecurityGroupRules": [
                    {
                        "SecurityGroupRuleId": "sgr-08f73fd74756de016",
                        "GroupId": "sg-002fc945e5ffc935f",
                        ...
                    }
                ],
                "ResponseMetadata": {
                    "RequestId": "3fad4a26-6913-43a0-8a86-e0aa5fe97e15",
                    ...
                }
            }
        }
    ],
    "us-west-2": [],
    "us-east-2": []
}
```

## Request | KeyError

The Lambda handler checks the event's type value and, in this case, expects the event to also include parameters `tag_key` and `cidr_block`. Lambda handler will attempt to variables based off these parameters from the event and if these parameters doesn't exist, a KeyError will be raised.

For example, if the event is being sent with `type = update_security_group_rule`, it **must** also have `tag_key = test_whitelist` (or which ever other supported tag key you wish to search by) and `cidr_block = 10.0.0.2/32` (a valid CIDR block to add to all matched SG's). Lambda handler will see the value of the parameter `type` and expect to also find a parameter `tag_key` and `cidr_block` in the event body.

Incorrect request event parameter `target_tag`, should be `tag_key`
```python
event = {
    "type"       : "update_security_group_rule",
    "target_key" : "test_whitelist",
    "cidr_block" : "10.0.0.2/32"
}
```

Request response
```python
{
    "error": [
        {
            "event_type": "update_security_group_rule",
            "message": "Request body for update_security_group_rule must include parameters tag_key and cidr_block. One or more parameters not found",
            "status": "error"
        }
    ]
}
```

## Request | ValueError

* tag_key - should be one of the following: ["test_whitelist", ]
* cidr_block - should be a valid CIDR block, e.g., "192.168.2.0/32"

> The Lambda restricts the allowable tag keys for updating Security Group rules to prevent inadvertent changes to ingress rules. This control measure ensures that only authorized and intended modifications are made, mitigating the risk of unintended alterations to Security Group configurations.

Incorrect value for parameter tag_key `whitelist`, should be one of the following: ["test_whitelist", ].
```python
event = {
    "type"       : "update_security_group_rule",
    "tag_key"    : "whitelist",
    "cidr_block" : "10.0.0.2/32"
}
```

Request response
```python
{
    "error": [
        {
            "event_type": "update_security_group_rule",
            "message": "Request body for update_security_group_rule has invalid tag_key: whitelist, must be one of the following: ['test_whitelist']",
            "status": "error"
        }
    ]
}
```

Incorrect value for parameter cidr_block `10.0,2.0/32`, should be a valid CIDR block, e.g., "192.168.2.0/32".
```python
event = {
    "type"       : "update_security_group_rule",
    "tag_key"    : "whitelist",
    "cidr_block" : "10.0,2.0/32"
}
```

Request response
```python
{
    "error": [
        {
            "event_type": "update_security_group_rule",
            "message": "Request body for update_security_group_rule has invalid cidr_block: 10.0,2.0/32, must be a valid CIDR block, e.g., 192.168.2.0/32",
            "status": "error"
        }
    ]
}
```

## Request | No updates were made/needed

Same request repeated a second time as [Request no errors](#request--no-errors). Since the first request made all the updates, this second request should catch that all SG's that match the tag_key condition already have a ingress rule where the source CIDR is the provided cidr_block and the form:to port ranges match from the tag_key's value on the SG.

Request response
```python
{
    "us-east-1": [
        {
            "message": "SG sg-0931bff5d7a180d5a already had rules for this cidr:port-range combo"
        },
        {
            "message": "SG sg-0eec40bafd5628a81 already had rules for this cidr:port-range combo"
        }
    ],
    "us-west-1": [
        {
            "message": "SG sg-002fc945e5ffc935f already had rules for this cidr:port-range combo"
        }
    ],
    "us-west-2": [],
    "us-east-2": []
}
```
