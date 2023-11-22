# get_security_groups_by_cidr

Request event will include a cidr_block parameter. Lambda will search all Security Groups across all regions it has access to and find the SG's that have an ingress rule where the source cidr = cidr_block. 

The return for this request is a map. The key's of the map are the regions that were searched. Value of the key's are a list of all SG's that matched the condition (each item in list is a dictionary of SG data).

Basic response syntax can be found in this [Response](#request--no-errors) section.

# Response

## Request | no errors

Request event
```python
event = {
    "type"       : "get_security_groups_by_cidr",
    "cidr_block" : "10.0.0.2/32"
}
```

Request response
```python
{
    "region-1": [
        {
            "Description": "test SG description",
            "GroupName": "test-east-1",
            ...
        },
        {
            "Description": "443 needed",
            "GroupName": "test-2-east",
            ...
        }
    ],
    "region-2": [
        {
            "Description": "test SG description",
            "GroupName": "test-west-1",
            ...
        }
    ],
    "region-3": [],
    "region-4": []
}

```

## Request | KeyError

The Lambda handler checks the event's type value and hard codes the value for `search_by` accordingly. This hard coded search_by value is the expected parameter that should have also been sent in the event. Lambda handler will attempt to create the variable `search_for` by accessing this expected parameter from event and if that parameter doesn't exist, a KeyError will be raised.

For example, if the event is being sent with `type : get_security_groups_by_cidr`, it **must** also have `cidr_block : 10.0.0.1/26` (or which ever other ingress cidr block you wish to search by). Lambda handler will see the value of the parameter `type` and expect to also find a parameter `cidr_block` in the event body.

Incorrect request event parameter `cidr`, should be `cidr_block`.
```python
event = {
    "type"    : "get_security_groups_by_cidr",
    "cidr"    : "10.0.2.0/32"
}
```

Request response
```python
{
    "error": [
        {
            "event_type": "get_security_groups_by_cidr",
            "message": "Request body for get_security_groups_by_cidr must include parameter cidr_block. Parameter not found",
            "status": "error"
        }
    ]
}
```

> for event['type'] = "get_security_groups_by_tag", the expected parameter is "tag_key" instead of "cidr_block"

## Request | ValueError

Incorrect value for parameter cidr_block `10.0,2.0/32`, should be a valid CIDR block `10.0.2.0/32` (no commas).
```python
event = {
    "type"       : "get_security_groups_by_cidr",
    "cidr_block" : "10.0,2.0/32"
}
```

Request response
```python
{
    "error": [
        {
            "event_type": "get_security_groups_by_cidr",
            "message": "Request body for get_security_groups_by_cidr has invalid cidr_block: 10.0,2.0/32, must be a valid CIDR block, e.g., 192.168.2.0/32",
            "status": "error"
        }
    ]
}
```
