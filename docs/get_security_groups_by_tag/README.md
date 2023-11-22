# get_security_groups_by_tag

Request event will include a tag_key parameter. Lambda will search all Security Groups across all regions it has access to and find the SG's who's tag key = tag_key. 

The return for this request is a map. The key's of the map are the regions that were searched. Value of the key's are a list of all SG's that matched the condition (each item in list is a dictionary of SG data).

Basic response syntax can be found in this [Response](#request--no-errors) section.

# Response

## Request | no errors

Request event
```python
event = {
    "type"    : "get_security_groups_by_tag",
    "tag_key" : "test_whitelist"
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

For example, if the event is being sent with `type = get_security_groups_by_tag`, it **must** also have `tag_key = test_whitelist` (or which ever other supported tag key you wish to search by). Lambda handler will see the value of the parameter `type` and expect to also find a parameter `tag_key` in the event body.

Incorrect request event parameter `tag_keys`, should be `tag_key` (without the s)
```python
event = {
    "type"     : "get_security_groups_by_tag",
    "tag_keys" : "test_whitelist"
}
```

Request response
```python
{
    "error": [
        {
            "event_type": "get_security_groups_by_tag",
            "message": "Request body for get_security_groups_by_tag must include parameter tag_key. Parameter not found",
            "status": "error"
        }
    ]
}
```

> for event['type'] = "get_security_groups_by_cidr", the expected parameter is "cidr_block" instead of "tag_key"

## Request | ValueError

Incorrect value for parameter tag_key `whitelist`, should be one of the following: ["test_whitelist", ].
```python
event = {
    "type"    : "get_security_groups_by_tag",
    "tag_key" : "whitelist"
}
```

Request response
```python
{
    "error": [
        {
            "event_type": "get_security_groups_by_tag",
            "message": "Request body for get_security_groups_by_tag has invalid tag_key: whitelist, must be one of the following: ['test_whitelist']",
            "status": "error"
        }
    ]
}
```
