# i don't like it, doesn't work as expected
def lambda_handler(event, context):
    regions = ["us-east-1", "us-west-1", "us-west-2", "us-east-2"]
    supported_event_types = ["get_security_groups_by_tag", "get_security_groups_by_cidr", "validate_cidr_exists", "update_security_group_rule"]
    data = {}

    event_type = event["type"]

    if event_type not in supported_event_types:
        data["error"] = {"message": f"event type {event_type} not supported, must be one of the following: {str(supported_event_types)}"}
    else:
        if event_type == "validate_cidr_exists":
            data = validate_cidr_exists("sg_id", event.get("sg_id"), event.get("region"), event.get("cidr_block"))
        elif event_type == "update_security_group_rule":
            data = update_security_group_rule(event["cidr_block"], event["tag_key"], regions)
        else:
            search_by  = "tag_key" if event_type == "get_security_groups_by_tag" else "cidr_block"
            search_for = event[search_by]
            
            for region in regions:
                response = get_security_groups(search_by, search_for, region)
                
                if isinstance(response, dict) and not response.get("error"):
                    data[region] = response
                else:
                    error_message = response.get("error") if isinstance(response, dict) else response
                    data[region] = [{"error": error_message}]
                
    pretty_output = json.dumps(data, indent=4)
    log.info(pretty_output)


