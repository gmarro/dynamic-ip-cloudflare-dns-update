#!/usr/bin/env python3

import http.client, re, os

current_ip_url = "ifconfig.me"

cloudflare_api_url = "api.cloudflare.com"

update_dns_path_tmpl = "/client/v4/zones/{}/dns_records/{}/"


def main():
    #Getting environment variables
    zone_identifier = os.environ.get('CLOUDFLARE_ZONE_IDENTIFIER')
    dns_record_id = os.environ.get('CLOUDFLARE_RECORD_ID') 
    hostname = os.environ.get('CLOUDFLARE_HOSTNAME') 
    api_key = os.environ.get('CLOUDFLARE_API_KEY')
    auth_email = os.environ.get('CLOUDFLARE_AUTH_EMAIL')

    #Initializing variables
    update_dns_path = update_dns_path_tmpl.format(zone_identifier, dns_record_id)
    headers = {
        "Content-Type": "application/json",
        "Authorization" : "Bearer {}".format(api_key),
        "X-Auth-Email" : auth_email
    }

    #Getting current IP
    conn = http.client.HTTPSConnection(current_ip_url)
    
    conn.request("GET", "")

    res = conn.getresponse()
    data = res.read()

    # getting returned value
    current_ip = data.decode("utf-8").strip()

    # Check it is an IP address
    valid_ip = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", current_ip) 

    if valid_ip :
        print("IP valid : {}".format(current_ip))
    else :
        print("Returned value does not seem to be an IP : {}".format(data.decode("utf-8")))
        exit(1)

    #Compare it to IP configured in Cloudflare registered in ip.txt file locally
    f = open("../resources/ip.txt", "r")
    configured_ip = f.read()
    f.close()

    if configured_ip == current_ip :
        print("Nothing to do, IP has not changed")
    else :
        print("IP change detected, updating it on cloudflare")
        payload = """
        {{
            "comment" : "Automatic update of IP", 
            "type" : "A",
            "content" : "{}",
            "name" : "{}",
            "proxied" : true,
            "tags" : [],
            "ttl" : 1
        }}
        """.format(current_ip, hostname)

        conn = http.client.HTTPSConnection(cloudflare_api_url)

        conn.request("PATCH", update_dns_path, payload, headers)

        res = conn.getresponse()

        if res.status < 299 :
            data = res.read()

            print(data.decode("utf-8"))
            print("Change of IP address done")
            print("Update IP address in ip.txt file")
            f = open("../resources/ip.txt", "w")
            f.write(current_ip)
            f.close()

            print("Update IP address in ip.txt file done")
        else :
            print("Could not update IP in Cloudflare : HTTP Code {}, Reason : {}".format(res.status, res.reason))
            data = res.read()
            print(data.decode("utf-8"))


if __name__ == "__main__":
    main()
