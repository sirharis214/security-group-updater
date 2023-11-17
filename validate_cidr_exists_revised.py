def validate_cidr_exists(search_by, search_for, region, cidr_block):
    # check if given cidr exists in given sg
    # @param: search_by    - the filter name 
    # @param: search_for   - SG id to check
    # @param: region       - the region of the sg
    # @param: cidr_block   - the cidr to look for in sg's ingress rules
    # @return response     - wether the cidr exists in any of the ingress rule/s for 
    # given sg, if True, also return the from:to ports for matched rule
    if not is_valid_cidr(cidr_block):
        return {"error": "cidr_block must be a valid CIDR block, e.g., '10.0.2.0/32'"}

    sg = get_security_groups(search_by, search_for, region)
    if not sg:
        log.info(f"SG {search_for} in region {region} doesn't exist")
    else:
        rules = sg[0].get("IpPermissions")
        if not rules:
            log.info(f"SG {search_for} in region {region} doesn't have any ingress rules")
        else:
            response = next(({"exists": True, "from_port": rule["FromPort"], "to_port": rule["ToPort"]} for rule in rules if rule.get("IpRanges")[0].get("CidrIp") == cidr_block), {"exists": False})
            log.info(f"{cidr_block} exists as an ingress rule for {search_for}")
            return response

    return {"exists": False}
