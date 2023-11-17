import boto3
import json
import ipaddress
import logging

log = logging.getLogger()
log.setLevel(logging.INFO)


"""
Test update_security_group_rule
event = {
    "type"         : "update_security_group_rule",
    "tag_key"      : "test_whitelist",
    "cidr_block" : "10.0.0.2/32"
}

** us-east-1 **
we have 2 SG's that have a tag where key = tag_key

SG 1's tag key tag_key has a value of "[443]"
SG 1 has 2 rules:
    Rule 1: is not for the requested cidr
    Rule 2: is for the requested cidr and already has from:to port 443
    - Since the rule for cidr_block and port range already exists, there should be any changes to this SG
SG 2's tag key tag_key has a value of "443" (not in list)
SG 2 has 0 rules:
    - Since this SG has no rules, we should expect a rule created for this SG
    - source = cidr_block & from:to port's = 443

** us-west-1 **
we have 1 SG that have a tag where key = tag_key

SG 1's tag key tag_key has a value of "[443,22-23]"
SG 1 has 2 rules:
    Rule 1: is not for the requested cidr
    Rule 2: is for requested cidr and from:to port range is 22:23
    - Since this SG needs two rules for cidr_block: one for port 443-443 and one for 22-23 
        AND out of two rules, only one matches the cidr_block-port range combo,
        We should expect one rule to be created for this SG
    - source desicred_cidr $ from:to 443

** us-east-2 **
NO SG's have a tag where key = tag_key

** us-west-2 **
NO SG's have a tag where key = tag_key

- Check docs/update_security_group_rule.json for sample output of lambda_handler for this event
- Check docs/update_security_group_rule-output-log.csv for sample logs files for this event's lambda run
--------------
Test validate_cidr_exists
event = {
    "type"       : "validate_cidr_exists",
    "sg_id"      : "sg-0eec40bafd5628a81",
    "region"     : "us-east-1",
    "cidr_block" : "10.0.0.2/32"
}

--------------

Test search_by = cidr_block
event = {
    "type"       : "get_security_groups_by_cidr",
    "cidr_block" : "10.0.0.2/32"
}

* 1 SG in east-1
* 1 SG in west-1
* No SG's in east-2, west-2 should match
- Check docs/get_security_groups_by_cidr.json for sample output of lambda_handler for this event

--------------

Test search_by = tag_key
event = {
    "type"    : "get_security_groups_by_tag",
    "tag_key" : "test_whitelist"
}

* 2 SG's in east-1
* 1 SG in west-1
* No SG's in east-2, west-2 should match
- Check docs/get_security_groups_by_tag.json for sample output of lambda_handler for this event
"""


def create_rules(rules):
    # helper function for update_security_group_rule
    # given a list of rules that need to be created per SG - per region
    # @param: rules    - list of rules(dict) that need to be created across all regions for each SG
    # @return: results - list of each rule's creation status (dict)
    results = []  # Variable to store success or error for each rule

    for rule in rules:
        log.info(f"Creating rule: {rule}")
        ec2_client = boto3.client("ec2", region_name=rule.get("region"))

        try:
            response = ec2_client.authorize_security_group_ingress(
                GroupId=rule.get("sg_id"),
                IpPermissions=[
                    {
                        "FromPort": int(rule.get("from_port")),
                        "IpProtocol": "tcp",
                        "IpRanges": [
                            {
                                "CidrIp": rule.get("cidr_block"),
                                "Description": "test_whitelist created by haris/sg-updater",
                            },
                        ],
                        "ToPort": int(rule.get("to_port")),
                    },
                ],
                TagSpecifications=[
                    {
                        "ResourceType": "security-group-rule",
                        "Tags": [
                            {"Key": "Created_By", "Value": "haris/sg_updater"},
                        ],
                    },
                ],
            )

            # Rule creation was successful
            results.append({"rule": rule, "status": "success", "response": response})

        except Exception as e:
            # Rule creation encountered an error
            results.append({"rule": rule, "status": "error", "error_message": str(e)})
    return results


def generate_rule_for_sg(sg_id, region, cidr_block, port):
    # helper function for get_rules_to_create()
    # create a rule {} that will be added to rules = []
    # @param: sg_id      - SG ID to add the rule to
    # @param: region     - region of the SG
    # @param: cidr_block - the cidr_block for the rule
    # @param: port       - the from:to port range for the rule
    # @return: rule      - the rule dictionary that get_rules_to_create() will use to create the rule
    if isinstance(port, list):
        from_port = port[0]
        to_port = port[1]
    else:
        from_port = port
        to_port = port

    rule = {
        "sg_id": sg_id,
        "region": region,
        "cidr_block": cidr_block,
        "from_port": from_port,
        "to_port": to_port,
    }
    return rule


def get_rules_to_create(sg_id, region, cidr_block, new_ports, current_sg_rules):
    # helper function for update_security_group_rule
    # creates a list of rules to create for a given SG based on its required port ranges
    # @param: cidr_block: string
    # @param: new_ports: ['443'] or ['443', ['22','23'] ]
    # @param: current_sg_rules = list(dict)
    # we'll be given a list of rules for the current SG
    # we'll be given the requested cidr + port-ranges that cidr should have
    # ie: 10.0.0.2/32 :443  &  10.0.0.2/32 :22-23
    # we'll check if the SG already has rule/rules for the cidr + port-range combo's
    # @return: ports = [{}] list of rules(dict) that need to be created
    ports = []  # ports that we're not found for cidr_block
    rules = []  # returned; rules that need to be created

    # if current_sg_rules is empty list, ie: no rules in SG
    if not current_sg_rules:
        for port in new_ports:
            rule = generate_rule_for_sg(sg_id, region, cidr_block, port)
            rules.append(rule)
    else:
        # current_sg_rules has existing rules, we must check each one to see if the rule we want to create already exists
        for port in new_ports:
            for index, rule in enumerate(current_sg_rules):
                i = index + 1
                log.info(f"checking for port {port}")
                if rule.get("IpRanges")[0].get("CidrIp") == cidr_block:
                    log.info(f"checking_rule #{i}: {json.dumps(rule, indent=4)}")
                    log.info(f"rule's cidr matches cidr_block")
                    if isinstance(port, list):
                        # 2 number's port range: ['22', '23']
                        # does rule have 22-23 from:to
                        if (
                            str(rule.get("FromPort")) == port[0]
                            and str(rule.get("ToPort")) == port[1]
                        ):
                            # cidr_block with configured from:to ports already exists
                            log.info(
                                f"rule has required ports; from:{port[0]} - to:{port[1]}"
                            )
                            log.info(
                                "checking if port range was marked to be created..."
                            )
                            # remove port from create_rules_for if exist
                            temp_ports = ports.copy()
                            for p in temp_ports:
                                if port in ports:
                                    ports.remove(port)
                                    log.info(f"{port} removed from ports")
                                else:
                                    log.info(f"{port} was not marked to be created...")
                            break
                        else:
                            # cidr_block exists but the configured from:to ports don't match
                            # maybe need to create new rule for this SG with this port range, still more rules to check
                            log.info(
                                f"rule does not have required ports; from:{port[0]} - to:{port[1]}"
                            )
                            log.info(f"marking rule to be created for port {port}")
                            ports.append(port)
                    else:
                        # single number port range: '443'
                        # does rule have a 443 from:to
                        if (
                            str(rule.get("FromPort")) == port
                            and str(rule.get("ToPort")) == port
                        ):
                            # cidr_block with configured from:to ports already exists
                            log.info(
                                f"rule has required ports; from:{port} - to:{port}"
                            )
                            log.info(
                                "checking if port range was marked to be created..."
                            )
                            temp_ports = ports.copy()
                            for p in temp_ports:
                                if port in ports:
                                    ports.remove(port)
                                    log.info(f"{port} removed from ports")
                                else:
                                    log.info(f"{port} was not marked to be created...")
                            break
                        else:
                            # cidr_block exists but the configured from:to ports don't match
                            # maybe need to create new rule for this SG with this port range, still more rules to check
                            log.info(
                                f"rule does not have required ports; from:{port} - to:{port}"
                            )
                            log.info(f"marking rule to be created for port {port}")
                            ports.append(port)
                else:
                    log.info(f"checking_rule #{i}: rule not for our cidr_block")
        # create a list of rules that need to be created for this SG after we checked existing rules
        if ports:
            for port in ports:
                rule = generate_rule_for_sg(sg_id, region, cidr_block, port)
                rules.append(rule)

    return rules


def get_list_of_ports(ports):
    # @param: ports - string value of the SG's tag_key, needs to be converted to python list of ports(string)
    # helper function for update_security_group_rule
    # creates list of port ranges, port range where from:to are two diff port # are added to a sub-list
    # ports = "[443, 22-23]"
    ports_ = [x.strip() for x in ports.strip("[] ").split(",")]
    # ports_ = ['443'] or ['443', '22-23']

    new_ports = []
    for port in ports_:
        if "-" in str(port):
            start, end = map(int, str(port).split("-"))
            port_range = [str(i) for i in range(start, end + 1)]
            new_ports.append(port_range)
        else:
            new_ports.append(port)
    # new_ports = ['443'] or ['443', ['22', '23']]
    return new_ports


def update_security_group_rule(cidr_block, tag_key, regions):
    # @param: cidr_block - the cidr block to add to all SG's
    # @param: tag_key    - the tag_key to search all SG's by that will be updated
    # @param: regions    - the regions to search SG's
    # @return all_security_groups - key will be each region, value for each key will be list of all rules(dict)
    # that were created for an SG or
    # why the rule could not/was not created for that SG
    # 1. find all SG's that match the tag_key
    # 2. check the value of tag_key which is a list of ports the cidr should be attached to
    # 3. check if SG already contains a rule of cidr_block:port combo
    # 4. finally, if all above qualify. add rule and add a description

    # init a empty dict for all regions
    all_security_groups = {}

    # 1. find all SG's that have a tag key = tag_key
    for region in regions:
        search_by = "tag_key"
        matched_sgs = get_security_groups(search_by, tag_key, region)

        if not matched_sgs:
            log.info(
                f"No SG in {region} to update, none matched condition {search_by} : {tag_key}"
            )
            # set empty list for this region since no SG's had tag where key=tag_key
            all_security_groups[region] = []
        else:
            # we were able to find 1+ SG in this region that have a tag where the key=tag_key
            for index, sg in enumerate(matched_sgs):
                i = index + 1
                # 2. get the value of tag_key, which is a list of port ranges for the cidr
                tags_list = sg.get("Tags")
                for tag in tags_list:
                    if tag.get("Key") == tag_key:
                        ports = tag.get("Value")
                        # reformat value to convert any two-number port ranges to sub-list
                        # ['443', '22-23'] -> ['443', ['22', '23'] ]
                        new_ports = get_list_of_ports(ports)
                        # new_ports is now =  ['443'] or ['443', ['22', '23']]
                        # 3. check if SG already contains a rule of cidr_block:port combo
                        # get SG's ingress rules
                        current_sg_rules = sg.get("IpPermissions")
                        log.info(
                            f"SG #{i}: {sg.get('GroupId')} should have rules that match {cidr_block} with {new_ports}"
                        )
                        log.info(
                            f"SG #{i}: {sg.get('GroupId')} has {len(current_sg_rules)} rules"
                        )
                        # check if a rule already exists for the requested cidr
                        # returns list of rules that need to be created
                        required_rules = get_rules_to_create(
                            sg.get("GroupId"),
                            region,
                            cidr_block,
                            new_ports,
                            current_sg_rules,
                        )
                        if required_rules:
                            pretty_required_rules = json.dumps(required_rules, indent=4)
                            log.info(
                                f"Need to create rules for SG #{i} {sg.get('GroupId')}: {pretty_required_rules}"
                            )
                            # create the rules, returns a list(dict) with status of each rule creation
                            rules = create_rules(required_rules)
                            # add the rules that were created for this sg in this region to all_security_groups
                            if rules:
                                # if a list for this region already exists, add required_rules to it
                                if region in all_security_groups:
                                    all_security_groups[region].extend(required_rules)
                                else:
                                    all_security_groups[region] = required_rules
                            else:
                                # could not create rules for this SG
                                this_sg_error = [
                                    {
                                        "error": f"could not create rules for {sg.get('GroupId')}, see logs for more info"
                                    }
                                ]
                                if region in all_security_groups:
                                    all_security_groups[region].extend(this_sg_error)
                                else:
                                    all_security_groups[region] = this_sg_error
                        else:
                            # no rules need to be created for this sg
                            this_sg_message = [
                                {
                                    "message": f"SG {sg.get('GroupId')} already had rules for this cidr:port-range combo"
                                }
                            ]
                            if region in all_security_groups:
                                all_security_groups[region].extend(this_sg_message)
                            else:
                                all_security_groups[region] = this_sg_message
                            # log.info(f"{sg.get('GroupId')} already had rules for this cidr:port-range combo")
                    else:
                        # a tag we aren't looking for
                        # log.info(f"Tag {tag.get("Key")} not the tag we're looking for.")
                        pass

    return all_security_groups


def is_valid_cidr(ip_cidr):
    # helper function to validate cidr_block's
    try:
        # Attempt to create an IPv4 or IPv6 network object
        ip_network = ipaddress.ip_network(ip_cidr, strict=False)
        return True
    except ValueError:
        # If ValueError is raised, the input is not a valid CIDR block
        return False


def validate_cidr_exists(search_by, search_for, region, cidr_block):
    # check if given cidr exists in given sg
    # @param: search_by    - the filter name 
    # @param: search_for   - SG id to check
    # @param: region       - the region of the sg
    # @param: cidr_block   - the cidr to look for in sg's ingress rules
    # @return response    - wether the cidr exists in any of the ingress rule/s for 
    # given sg, if True, also return the from:to ports for matched rule
    
    # validate given cidr_block
    if not is_valid_cidr(cidr_block):
        return {"error":"cidr_block must be a valid cidr block ie: '10.0.2.0/32'."}
    
    # init response   
    response = {
        "exists" : False
    }

    # get sg from region
    sg = get_security_groups(search_by, search_for, region)
    if not sg:
        log.info(f"SG {search_for} in region {region} doesn't exist")
    else:
        # check if cidr_block exists as an ingress rule for this SG
        rules = sg[0].get("IpPermissions")
        if not rules:
            log.info(f"SG {search_for} in region {region} doesn't have any ingress rules")
        else:
            for rule in rules:
                if rule.get("IpRanges")[0].get("CidrIp") == cidr_block:
                    log.info(f"{cidr_block} exists as an ingress rule for {search_for}")
                    response.get("exists") = True
                    response["from_port"]  = rule.get("FromPort")
                    response["to_port"]    = rule.get("ToPort")
    
    return response


def get_security_groups(search_by, search_for, region):
    # @param: search_by  - search all SG's by "tag_key" or "cidr_block"
    # @param: search_for - if search_by="tag", search_for="tag_key" | search_by="cidr_block", search_for="cidr_block/mask"
    # @param: region     - the region to check SG's
    # @return: all_security_groups - list of all SG(dict) that match condition

    # Create a Boto3 EC2 client for this region
    ec2_client = boto3.client("ec2", region_name=region)

    # init a empty list for this region
    all_security_groups = []
    # error return
    error = {}

    # set filter_name based on search_by value.
    # if search_by=cidr_block, validate search_for value to be a valid cidr block.
    if search_by == "tag_key":
        filter_name = "tag-key"
    elif search_by == "cidr_block":
        if is_valid_cidr(search_for):
            filter_name = "ip-permission.cidr"
        else:
            error["error"] = {
                "region": region,
                "search_by": search_by,
                "search_for": search_for,
                "message": f"invalid search_for value, must be a valid cidr block ie: '10.0.2.0/32'.",
            }
            return error
    elif search_by == "sg_id":
        if search_for.startswith("sg-"):
            filter_name = "group-id"
        else:
            error["error"] = {
                "region": region,
                "search_by": search_by,
                "search_for": search_for,
                "message": f"invalid search_for value, must be a valid sg-id ie: 'sg-xxxx'.",
            }
            return error
    else:
        error["error"] = {
            "region": region,
            "search_by": search_by,
            "search_for": search_for,
            "message": f"invalid search_by value, must be one of the following - ['tag_name', 'cidr_block'].",
        }
        return error

    response = ec2_client.describe_security_groups(
        Filters=[
            {
                "Name": filter_name,
                "Values": [
                    search_for,
                ],
            },
        ]
    )

    if not response.get("SecurityGroups"):
        log.info(
            f"{region} has No SG's that matched condition {search_by} : {search_for}"
        )
    else:
        # 1+ SG matched filter condition
        # all_security_groups = [{sg-data-1},{sg-data-2}]
        all_security_groups = response.get("SecurityGroups")
        log.info(
            f"{region} has {len(all_security_groups)} SG's that matched condition {search_by} : {search_for}"
        )

    return all_security_groups


def lambda_handler(event, context):
    # Define the regions you want to query
    regions = ["us-east-1", "us-west-1", "us-west-2", "us-east-2"]
    data = {}

    if event["type"] == "get_security_groups_by_tag":
        # search_by = "tag_key"
        search_by = "error_key"
        search_for = event["tag_key"]
        for region in regions:
            response = get_security_groups(search_by, search_for, region)
            if not response.get("error"):
                data[region] = response
            else:
                data[region] = [response.get("error")]
    elif event["type"] == "get_security_groups_by_cidr":
        search_by = "cidr_block"
        search_for = event["cidr_block"]
        for region in regions:
            response = get_security_groups(search_by, search_for, region)
            if not response.get("error"):
                data[region] = response
            else:
                data[region] = response.get("error")
            data[region] = response
    elif event["type"] == "validate_cidr_exists":
        search_by  = "sg_id"
        search_for = event.get("sg_id")
        region     = event.get("region")
        cidr_block = event.get("cidr_block")
        response   = validate_cidr_exists(search_by, search_for, region, cidr_block)
        data       = response
    elif event["type"] == "update_security_group_rule":
        cidr_block = event["cidr_block"]
        tag_key = event["tag_key"]
        response = update_security_group_rule(cidr_block, tag_key, regions)
        # rules that were created or not
        data = response

    pretty_output = json.dumps(data, indent=4)
    log.info(pretty_output)
