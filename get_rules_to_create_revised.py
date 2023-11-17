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
