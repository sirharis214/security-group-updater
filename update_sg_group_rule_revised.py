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
