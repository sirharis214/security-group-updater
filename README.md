# security-group-updater

Update Security Group (SG) rules in any region the Lambda has access into by scanning for a tag key of (one of the following) `[test-whitelist, ]`

> The Lambda restricts the allowable tag keys for updating Security Group rules to prevent inadvertent changes to ingress rules. This control measure ensures that only authorized and intended modifications are made, mitigating the risk of unintended alterations to Security Group configurations.

# Capabilities  

1. Get all SG's with a given tag_name
2. Get all SG's with a given cidr_block
3. Validate if a given sg_id in the given region has an ingress rule where the source is the given cidr_block
4. Update all SG's with a new ingress rule where the source is the given cidr_block (only updates all SG's that have a tag key = given tag_key)
    - checks ingress rules of each SG that has a tag key where the key = tag_key
    - tag value is the port ranges that should be open in this SG for any given cidr_block
    - for each SG, if an ingress rule for new given cidr_block and port-range already exists, a message is returned that this SG already had the requested cidr_block + port-range combo.
    - for each SG, if an ingress rule for new given cidr_block and port-range doesn't exist, rule is created and a dictionary is returned. The return dictionary per SG includes `rule` (dict) which includes details of the rule that was created, the `status` (string) of the api call made to create the rule and `response`(dict) of the api call made to create the rule. 
        
# Lambda Test Events

Here are the test events you can create in the Lambda console to test these functions for a valid response. Details on how the Lambda processes each type of event and the kind of errors it handles are documented [here](./docs/)

## get_sg_by_cidr

See [response.json](./docs/get_security_groups_by_cidr/response.json) for the Lambda's returned response for this event request. 

* Scenario:
    - 1 SG in us-east-1 has an ingress rule where the source CIDR is the event's cidr_block
    - 1 SG in us-west-1 has an ingress rule where the source CIDR is the event's cidr_block
    - No SG's in us-east-2 or us-west-2 have ingress rules where the source CIDR is the event's cidr_block

```python
event = {
    "type"       : "get_security_groups_by_cidr",
    "cidr_block" : "10.0.0.2/32"
}
```

## get_sg_by_tag

See [response.json](./docs/get_security_groups_by_tag/response.json) for the Lambda's returned response for this event request. 

* Scenario:
    - 2 SG in us-east-1 have a tag where the key is the event's tag_key
    - 1 SG in us-west-1 has a tag where the key is the event's tag_key
    - No SG's in us-east-2 or us-west-2 have a tag where the key is the event's tag_key

```python
event = {
    "type"    : "get_security_groups_by_tag",
    "tag_key" : "test_whitelist"
}
```

## validate_cidr_exists

See [response.json](./docs/validate_cidr_exists/response.json) for the Lambda's returned response for this event request.

* Scenario:
    - The given SG in us-east-1 **does** have a ingress rule where the source is the event's cidr_block

```python
event = {
    "type"       : "validate_cidr_exists",
    "sg_id"      : "sg-0eec40bafd5628a81",
    "region"     : "us-east-1",
    "cidr_block" : "10.0.0.2/32"
}
```

## update_sg_rule

See [response.json](./docs/update_security_group_rule/response.json) for the Lambda's returned response for this event request.

* Scenario:
    - us-east-1
        - Two SG's have a tag where key = tag_key
            - SG #1: tag_key has a value of "[443]" and a ingress rule for event's cidr_block with this port range already exists
            - SG #2: tag_key has a value of "443" (no list brackets) and there are no ingress rules at all. A rule will be created for SG #2.
    - us-west-1
        - One SG has a tag where key = tag_key
            - SG #1: tag_key has a value of "[443,22-23]" and a ingress rule for events cidr_block with port range 22:23 already exists. An ingress rule will be created for this SG for the events cidr_block with the port range 443.
    - us-east-2
        - No SG's have a tag where key = tag_key 
    - us-west-2
        - No SG's have a tag where key = tag_key

```python
event = {
    "type"         : "update_security_group_rule",
    "tag_key"      : "test_whitelist",
    "cidr_block"   : "10.0.0.2/32"
}
```
