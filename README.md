# security-group-updater
update Security Group (SG) rules in any region the Lambda has access into by scanning for a tag key of (one of the following) `[test-whitelist, ]`

# Capabilities

* Get all SG's with a given tag_name
* Get all SG's with a given CIDR block
* Validate if a given SG has a given CIDR
* Update all SG's with a new CIDR based on tag_name
    - checks each SG if rule for new CIDR and port-range pulled from tag_name already exists
        
# To Do

I want the data={} output to me uniform

data's output (return of request) should always be:

```python
{
    "key":[
        {},
    ]
}
```

* No errors
```python
{
    "region":[
        {
            "SG-data":"SG-data"
        }
    ]
}

```

* region has error
```python
{
    "region":[
        {   
            "status" : "error",
            "SG-data": "SG-data"
        }
    ]
}

```

* request has error
```python
{
    "error":[
        {   
            "status" : "error",
            "request-data": "request-data"
        }
    ]
}

```