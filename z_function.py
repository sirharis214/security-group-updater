import boto3
import json
import ipaddress
import logging

log = logging.getLogger()
log.setLevel(logging.INFO)


"""
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
--------------
Test validate_cidr_exists
event = {
    "type"       : "validate_cidr_exists",
    "sg_id"      : "sg-0eec40bafd5628a81",
    "region"     : "us-east-1",
    "cidr_block" : "10.0.0.2/32"
}
--------------
Test update_security_group_rule
event = {
    "type"         : "update_security_group_rule",
    "tag_key"      : "test_whitelist",
    "cidr_block"   : "10.0.0.2/32"
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
    from_port, to_port = (port[0], port[1]) if isinstance(port, list) else (port, port)
    return {
        "sg_id": sg_id,
        "region": region,
        "cidr_block": cidr_block,
        "from_port": from_port,
        "to_port": to_port,
    }


def get_rules_to_create(sg_id, region, cidr_block, new_ports, current_sg_rules):
    # helper function for update_security_group_rule
    # creates a list of rules to create for a given SG based on its required port ranges
    # @param: cidr_block: string
    # @param: new_ports: ['443'] or ['443', ['22','23'] ]
    # @param: current_sg_rules = list(dict)
    # @return: rules = [{}] list of rules(dict) that need to be created
    # we'll be given a list of rules for the current SG
    # we'll be given the requested cidr + port-ranges that cidr should have
    # ie: 10.0.0.2/32 :443  &  10.0.0.2/32 :22-23
    # we'll check if the SG already has rule/rules for the cidr + port-range combo's
    ports = []  # ports that were not found for cidr_block
    rules = []  # returned; rules that need to be created

    if not current_sg_rules:
        # current SG doesn't have any rules, nothing to validate just generate new rules
        rules = [generate_rule_for_sg(sg_id, region, cidr_block, port) for port in new_ports]
    else:
        # current SG has existing rules, we must check each one to see if the rule we want to create already exists
        for port in new_ports:
            for index, rule in enumerate(current_sg_rules, start=1):
                log.info(f"checking for port {port}")
                if rule.get("IpRanges")[0].get("CidrIp") == cidr_block:
                    log.info(f"checking_rule #{index}: {json.dumps(rule, indent=4)}")
                    if isinstance(port, list) and (
                        str(rule.get("FromPort")) == port[0]
                        and str(rule.get("ToPort")) == port[1]
                    ) or (
                        str(rule.get("FromPort")) == str(rule.get("ToPort")) == port
                    ):
                        # cidr_block with configured from:to ports already exists
                        log.info(f"rule has required ports; {port}")
                        log.info("removing port range if it was marked to be created...")
                        temp_ports = ports.copy()
                        for p in temp_ports:
                            if port in ports:
                                ports.remove(port)
                        break
                    else:
                        log.info(f"marking rule to be created for port {port}")
                        ports.append(port)
                else:
                    log.info(f"checking_rule #{index}: rule not for our cidr_block")
        if ports:
            rules = [generate_rule_for_sg(sg_id, region, cidr_block, port) for port in ports]

    return rules


def get_list_of_ports(ports):
    # @param: ports - string value of the SG's tag_key, needs to be converted to python list of ports(string)
    # helper function for update_security_group_rule
    # creates list of port ranges, port range where from:to are two diff port # are added to a sub-list
    # ports = "[443, 22-23]" -> ['443'] or ['443', '22-23']
    ports_ = [x.strip() for x in ports.strip("[] ").split(",")]
    
    new_ports = []
    for port in ports_:
        if "-" in str(port):
            start, end = map(int, str(port).split("-"))
            port_range = [str(i) for i in range(start, end + 1)]
            new_ports.append(port_range)
        else:
            new_ports.append(port)
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
    # 4. finally, create rules
    all_security_groups = {}

    for region in regions:
        # 1. find all SG's that have a tag key = tag_key
        search_by = "tag_key"
        matched_sgs = get_security_groups(search_by, tag_key, region)

        if not matched_sgs:
            log.info(f"No SG in {region} to update, none matched condition {search_by} : {tag_key}")
            all_security_groups[region] = []
        else:
            for index, sg in enumerate(matched_sgs, start=1):
                # 2. get the value of tag_key for this SG, which is a list of port ranges for the cidr
                tags_list = sg.get("Tags", [])
                ports = next((tag.get("Value") for tag in tags_list if tag.get("Key") == tag_key), [])
                # reformat value to convert any two-number port ranges to sub-list; "[443, 22-23]" -> ['443', ['22', '23']]
                new_ports = get_list_of_ports(ports)
                # 3. check if a rule of cidr_block:port combo already exists in this SG
                current_sg_rules = sg.get("IpPermissions", [])
                log.info(f"SG #{index}: {sg.get('GroupId')} should have rules that match {cidr_block} with {new_ports}")
                log.info(f"SG #{index}: {sg.get('GroupId')} has {len(current_sg_rules)} rules")
                # returns list of rules that need to be created
                required_rules = get_rules_to_create(sg.get("GroupId"), region, cidr_block, new_ports, current_sg_rules)

                # 4. finally, create rules
                if required_rules:
                    pretty_required_rules = json.dumps(required_rules, indent=4)
                    log.info(f"Need to create rules for SG #{index} {sg.get('GroupId')}: {pretty_required_rules}")
                    rules = create_rules(required_rules)
                    all_security_groups.setdefault(region, []).extend(rules)
                else:
                    this_sg_message = [{"message": f"SG {sg.get('GroupId')} already had rules for this cidr:port-range combo"}]
                    all_security_groups.setdefault(region, []).extend(this_sg_message)

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
    # @return response     - {} wether the cidr exists in any of the ingress rule/s for 
    # given sg, if True, also return the from:to ports for matched rule
    if not is_valid_cidr(cidr_block):
        error_message = f"invalid value cidr_block: {cidr_block}, must be a valid CIDR block, e.g., '10.0.2.0/32'."
        error = {"search_for": search_for, "cidr_block": cidr_block, "message": error_message, "status": "error"}
        return [error]

    sg = get_security_groups(search_by, search_for, region)
    if not sg:
        log.info(f"SG {search_for} in region {region} doesn't exist")
    else:
        rules = sg[0].get("IpPermissions")
        if not rules:
            log.info(f"SG {search_for} in region {region} doesn't have any ingress rules")
        else:
            response = next(({"exists": True, "from_port": rule["FromPort"], "to_port": rule["ToPort"]} for rule in rules if rule.get("IpRanges")[0].get("CidrIp") == cidr_block), {"exists": False})
            log.info(f"SG {search_for} does have an ingress rule for {cidr_block}")
            return response

    return {"exists": False}


def get_security_groups(search_by, search_for, region):
    # @param: search_by  - search all SG's by "tag_key" or "cidr_block"
    # @param: search_for - if search_by="tag", search_for="tag_key" | search_by="cidr_block", search_for="cidr_block/mask"
    # @param: region     - the region to check SG's
    # @return: all_security_groups - list of all SG(dict) that match condition

    # Create a Boto3 EC2 client for this region
    ec2_client = boto3.client("ec2", region_name=region)

    # init a empty list for this region
    # all_security_groups = []
    # error return
    error = {}
    # Set filter_name based on search_by value.
    if search_by == "tag_key":
        filter_name = "tag-key"
    elif search_by == "cidr_block":
        if is_valid_cidr(search_for):
            filter_name = "ip-permission.cidr"
        else:
            error_message = f"invalid value search_for: {search_for}, must be a valid CIDR block, e.g., '10.0.2.0/32'."
            error = {"region": region, "search_by": search_by, "search_for": search_for, "message": error_message, "status": "error"}
            return [error]
    elif search_by == "sg_id":
        if search_for.startswith("sg-"):
            filter_name = "group-id"
        else:
            error_message = f"invalid value search_for: {search_for}, must be a valid security group ID, e.g., 'sg-0000'."
            error = {"region": region, "search_by": search_by, "search_for": search_for, "message": error_message, "status": "error"}
            return [error]
    elif search_by not in ["tag_key", "cidr_block", "sg_id"]:
        error_message = f"invalid value search_by: {search_for}, must be one of the following - ['tag_key', 'cidr_block', 'sg_id']."
        error = {"region": region, "search_by": search_by, "search_for": search_for, "message": error_message, "status": "error"}
        return [error]

    response = ec2_client.describe_security_groups(
        Filters=[
            {
                "Name": filter_name,
                "Values": [search_for],
            },
        ]
    )

    all_security_groups = response.get("SecurityGroups", [])

    if not all_security_groups:
        log.info(f"{region} has No SG's that matched condition {search_by} : {search_for}")
    else:
        log.info(f"{region} has {len(all_security_groups)} SG's that matched condition {search_by} : {search_for}")

    return all_security_groups


def lambda_handler(event, context):
    regions = ["us-east-1", "us-west-1", "us-west-2", "us-east-2"]
    supported_event_types = ["get_security_groups_by_tag", "get_security_groups_by_cidr", "validate_cidr_exists", "update_security_group_rule"]
    data = {}

    event_type = event["type"]

    if event_type not in supported_event_types:
        data["error"] = {"message": f"event type {event_type} not supported, must be one of the following: {str(supported_event_types)}"}
    else:
        if event_type == "validate_cidr_exists":
            search_for = event.get("sg_id")
            region     = event.get("region")
            cidr_block = event.get("cidr_block")
            data[region] = [ validate_cidr_exists("sg_id", search_for, region, cidr_block) ]
        elif event_type == "update_security_group_rule":
            data = update_security_group_rule(event["cidr_block"], event["tag_key"], regions)
        else:
            try:
                search_by  = "tag_key" if event_type == "get_security_groups_by_tag" else "cidr_block"
                search_for = event[search_by]
                for region in regions:
                    response = get_security_groups(search_by, search_for, region)
                    data[region] = response
            except KeyError as e:
                error_message = f"Request body for {event_type} must include a key {search_by}. Key not found"
                error = {"event_type": event_type, "search_by": search_by, "message": error_message, "status": "error"}
                log.error(error_message)
                data["error"] = [error]
            except Exception as e:
                error_message = f"Error: {str(e)}"
                error = {"event_type": event_type, "search_by": search_by, "message": error_message, "status": "error"}
                log.error(error_message)
                data["error"] = [error]
                
    pretty_output = json.dumps(data, indent=4)
    log.info(pretty_output)
    