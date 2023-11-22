# validate_cidr_exists

Request event will include parameters sg_id, region and cidr_block. Lambda will search the provided region for the provided sg_id and confirm if it has an ingress rule where the source CIDR is the same as provided cidr_block.

The return for this request is a map. The key of the map is the region that was searched. Value of the key is a list of a dictionary that matched the condition with it's from_port to_port details.

Basic response syntax can be found in this [Response](#request--no-errors) section.

# Response

## Request | no errors

Request event
```python
event = {
    "type"       : "validate_cidr_exists",
    "sg_id"      : "test_whitelist",
    "region"     : "region-1",
    "cidr_block" : "10.0.2.0/32"
}
```

Request response
```python
{
    "region-1": [
        {
            "exists": true,
            "from_port": 443,
            "to_port": 443
        }
    ]
}
```

## Request | KeyError

The Lambda handler checks the event's type value and hard codes the value for `search_by` accordingly. This hard coded search_by value is the expected parameter that should have also been sent in the event. Lambda handler will attempt to create the variable `search_for` by accessing this expected parameter as well as 2 other parameters from event and if any of those parameter don't exist, a KeyError will be raised.

For example, if the event is being sent with `type = validate_cidr_exists`, it **must** also have `sg_id = sg-000`, `region = us-east-1` and `cidr_block = 10.0.2.0/32` (values are examples). Lambda handler will see the value of the parameter `type` and expect to also find the parameters `sg_id`, `region` and `cidr_block` in the event body.

Incorrect request event parameter `sgid`, should be `sg_id`
```python
event = {
    "type"       : "validate_cidr_exists",
    "sgid"       : "sg-0eec40bafd5628a81",
    "region"     : "us-east-1",
    "cidr_block" : "10.0.2.0/32"
}
```

Request response
```python
{
    "error": [
        {
            "event_type": "validate_cidr_exists",
            "message": "Request body for validate_cidr_exists must include parameters sg_id, region, cidr_block. One or more parameters not found'",
            "status": "error"
        }
    ]
}
```

## Request | ValueError

* sg_id - should be a valid Security Group ID beginning with `sg-`
* region - should be one of the following: ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]
* cidr_block - should be a valid CIDR block, e.g., "192.168.2.0/32"

Incorrect value for parameter sg_id `sg0eec40bafd5628a81`, should start with `sg-`.
```python
event = {
    "type"       : "validate_cidr_exists",
    "sg_id"      : "sg0eec40bafd5628a81",
    "region"     : "us-east-1",
    "cidr_block" : "10.0.2.0/32"
}
```

Request response
```python
{
    "error": [
        {
            "event_type": "validate_cidr_exists",
            "message": "Request body for validate_cidr_exists has one or more invalid parameter, must be valid values: sg_id = 'sg-0000', cidr_block = '10.0.2.0/32', region = must be one of the following: ['us-east-1', 'us-west-1', 'us-west-2', 'us-east-2']",
            "status": "error"
        }
    ]
}
```
