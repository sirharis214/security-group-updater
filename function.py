import boto3
import json
import ipaddress
import logging

log = logging.getLogger()
log.setLevel(logging.INFO)

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
        rules = [
            generate_rule_for_sg(sg_id, region, cidr_block, port) for port in new_ports
        ]
    else:
        # current SG has existing rules, we must check each one to see if the rule we want to create already exists
        for port in new_ports:
            for index, rule in enumerate(current_sg_rules, start=1):
                log.info(f"checking for port {port}")
                if rule.get("IpRanges")[0].get("CidrIp") == cidr_block:
                    log.info(f"checking_rule #{index}: {json.dumps(rule, indent=4)}")
                    if (
                        isinstance(port, list)
                        and (
                            str(rule.get("FromPort")) == port[0]
                            and str(rule.get("ToPort")) == port[1]
                        )
                        or (
                            str(rule.get("FromPort")) == str(rule.get("ToPort")) == port
                        )
                    ):
                        # cidr_block with configured from:to ports already exists
                        log.info(f"rule has required ports; {port}")
                        log.info(
                            "removing port range if it was marked to be created..."
                        )
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
            rules = [
                generate_rule_for_sg(sg_id, region, cidr_block, port) for port in ports
            ]

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
            log.info(
                f"No SG in {region} to update, none matched condition {search_by} : {tag_key}"
            )
            all_security_groups[region] = []
        else:
            for index, sg in enumerate(matched_sgs, start=1):
                # 2. get the value of tag_key for this SG, which is a list of port ranges for the cidr
                tags_list = sg.get("Tags", [])
                ports = next(
                    (
                        tag.get("Value")
                        for tag in tags_list
                        if tag.get("Key") == tag_key
                    ),
                    [],
                )
                # reformat value to convert any two-number port ranges to sub-list; "[443, 22-23]" -> ['443', ['22', '23']]
                new_ports = get_list_of_ports(ports)
                # 3. check if a rule of cidr_block:port combo already exists in this SG
                current_sg_rules = sg.get("IpPermissions", [])
                log.info(
                    f"SG #{index}: {sg.get('GroupId')} should have rules that match {cidr_block} with {new_ports}"
                )
                log.info(
                    f"SG #{index}: {sg.get('GroupId')} has {len(current_sg_rules)} rules"
                )
                # returns list of rules that need to be created
                required_rules = get_rules_to_create(
                    sg.get("GroupId"), region, cidr_block, new_ports, current_sg_rules
                )

                # 4. finally, create rules
                if required_rules:
                    pretty_required_rules = json.dumps(required_rules, indent=4)
                    log.info(
                        f"Need to create rules for SG #{index} {sg.get('GroupId')}: {pretty_required_rules}"
                    )
                    rules = create_rules(required_rules)
                    all_security_groups.setdefault(region, []).extend(rules)
                else:
                    this_sg_message = [
                        {
                            "message": f"SG {sg.get('GroupId')} already had rules for this cidr:port-range combo"
                        }
                    ]
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
    # for the given sg, if True, return the from:to ports for matched rule

    sg = get_security_groups(search_by, search_for, region)
    if not sg:
        log.info(f"SG {search_for} in region {region} doesn't exist")
    else:
        rules = sg[0].get("IpPermissions")
        if not rules:
            log.info(
                f"SG {search_for} in region {region} doesn't have any ingress rules"
            )
        else:
            response = next(
                (
                    {
                        "exists": True,
                        "from_port": rule["FromPort"],
                        "to_port": rule["ToPort"],
                    }
                    for rule in rules
                    if rule.get("IpRanges")[0].get("CidrIp") == cidr_block
                ),
                {"exists": False},
            )
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

    supported_search_by = ["tag_key", "cidr_block", "sg_id"]

    # Set filter_name based on search_by value.
    if search_by == "tag_key":
        filter_name = "tag-key"
    elif search_by == "cidr_block":
        filter_name = "ip-permission.cidr"
    elif search_by == "sg_id":
        filter_name = "group-id"
    elif search_by not in supported_search_by:
        error_message = f"invalid value search_by: {search_by}, must be one of the following: {str(supported_search_by)}"
        return [
            {
                "region": region,
                "search_by": search_by,
                "search_for": search_for,
                "message": error_message,
                "status": "error",
            }
        ]

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
        log.info(
            f"{region} has No SG's that matched condition {search_by} : {search_for}"
        )
    else:
        log.info(
            f"{region} has {len(all_security_groups)} SG's that matched condition {search_by} : {search_for}"
        )

    return all_security_groups


def lambda_handler(event, context):
    regions = ["us-east-1", "us-west-1", "us-west-2", "us-east-2"]
    supported_event_types = [
        "get_security_groups_by_tag",
        "get_security_groups_by_cidr",
        "validate_cidr_exists",
        "update_security_group_rule",
    ]
    supported_tag_keys = ["test_whitelist"]
    data = {}

    event_type = event["type"]

    if event_type not in supported_event_types:
        error_message = f"Request body has invalid event type: {event_type}, must be one of the following: {str(supported_event_types)}"
        data["error"] = [{"message": error_message, "status": "error"}]
        log.error(error_message)
    else:
        try:
            # validate_cidr_exists
            if event_type == "validate_cidr_exists":
                search_by = "sg_id"
                search_for = event.get(search_by)
                region = event.get("region")
                cidr_block = event.get("cidr_block")

                if (
                    search_by not in event
                    or "region" not in event
                    or "cidr_block" not in event
                ):
                    error_message = f"Request body for {event_type} must include parameters {search_by}, region, cidr_block. One or more parameters not found"
                    raise KeyError(error_message)

                if (
                    not search_for.startswith("sg-")
                    or not is_valid_cidr(cidr_block)
                    or region not in regions
                ):
                    error_message = f"Request body for {event_type} has one or more invalid parameter, must be valid values: sg_id = 'sg-0000', cidr_block = '10.0.2.0/32', region = must be one of the following: {str(regions)}"
                    raise ValueError(error_message)
                else:
                    data[region] = [
                        validate_cidr_exists(search_by, search_for, region, cidr_block)
                    ]
            # update_security_group_rule
            elif event_type == "update_security_group_rule":
                cidr_block = event.get("cidr_block")
                tag_key = event.get("tag_key")

                if "cidr_block" not in event or "tag_key" not in event:
                    error_message = f"Request body for {event_type} must include parameters tag_key and cidr_block. One or more parameters not found"
                    raise KeyError(error_message)

                if not is_valid_cidr(cidr_block):
                    error_message = f"Request body for {event_type} has invalid cidr_block: {cidr_block}, must be a valid CIDR block, e.g., 192.168.2.0/32"
                    raise ValueError(error_message)

                if tag_key not in supported_tag_keys:
                    error_message = f"Request body for {event_type} has invalid tag_key: {tag_key}, must be one of the following: {supported_tag_keys}"
                    raise KeyError(error_message)
                # all validations passed
                data = update_security_group_rule(cidr_block, tag_key, regions)
            # get_security_groups_by_tag or get_security_groups_by_cidr
            else:
                search_by = (
                    "tag_key"
                    if event_type == "get_security_groups_by_tag"
                    else "cidr_block"
                )

                # search_for = search_by value, if request body is missing the expected search_by param, raise KeyError
                if search_by in event:
                    search_for = event.get(search_by)
                else:
                    error_message = f"Request body for {event_type} must include parameter {search_by}. Parameter not found"
                    raise KeyError(error_message)

                # validate the value of search_for
                if search_by == "tag_key" and search_for not in supported_tag_keys:
                    error_message = f"Request body for {event_type} has invalid {search_by}: {search_for}, must be one of the following: {str(supported_tag_keys)}"
                    raise ValueError(error_message)

                if search_by == "cidr_block" and not is_valid_cidr(search_for):
                    error_message = f"Request body for {event_type} has invalid {search_by}: {search_for}, must be a valid CIDR block, e.g., 192.168.2.0/32"
                    raise ValueError(error_message)

                # all validations have passed
                for region in regions:
                    response = get_security_groups(search_by, search_for, region)
                    data[region] = response
        except (KeyError, ValueError, Exception) as e:
            error_message = str(e)
            error = {
                "event_type": event_type,
                "message": error_message,
                "status": "error",
            }
            log.error(error_message)
            data["error"] = [error]

    pretty_output = json.dumps(data, indent=4)
    log.info(pretty_output)
