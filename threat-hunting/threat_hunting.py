#!/usr/bin/env python

from pprint import pprint
from threatresponse import ThreatResponse
import webexteamssdk
from functions import *


# If this script is the "main" script, run...
if __name__ == "__main__":
    pprint(get_amp_event_types())

# Set the correct computer name to the variable.
amp_computer_name = "Demo_TeslaCrypt"

amp_computer_list = get_amp_computers()
print(white("\nStep 1"))
print(green(f"Fetched Cisco Secure Endpoint Computer List\n"))

# iterate through each computer record
for computer in amp_computer_list:
    # If computer name matches, fetch that computer GUID
    if computer["hostname"] == amp_computer_name:
        amp_computer_guid = computer["connector_guid"]
        print(green(f"\nCisco Secure Endpoint Computer:\n{amp_computer_guid}"))

# Create query line to fetch Malware Executed and Threat Detected events for specific computer guid
amp_query_params = f"connector_guid[]={amp_computer_guid}&event_type[]=1107296272&event_type[]=1090519054"

# Call the function with the query line as an input and print the result
amp_event_list = get_amp_events(query_params=amp_query_params)
print(green(f"Retrieved {len(amp_event_list)} events from Cisco Secure Endpoint"))

# If events found, print the first events and save the hash of malicious file that was detected
if len(amp_event_list) > 0:
    amp_event = amp_event_list[0]
    print (green(f"First Event: {amp_event['event_type']} \
        \nDetection: {amp_event['detection']} \
        \nFile name: {amp_event['file']['file_name']} \
        \nFile sha256: {amp_event['file']['identity']['sha256']}"))

    threatgrid_sha = amp_event["file"]["identity"]["sha256"]
else:
    print("There are no AMP events\n\n")

print(white(f"\nStep 2"))

amp_computer_isolation = amp_isolation('get',amp_computer_guid)

if amp_computer_isolation:
    print(green(f"Computer {amp_computer_name} (GUID {amp_computer_guid}) is {amp_computer_isolation['status']}"))



amp_scd_list = get_amp_scds()

print(green(f"Fetched Secure Endpoint Simple Custom Detection Lists"))

for scd in amp_scd_list:
    if scd["name"] == "Simple Custom Detection List":
        amp_scd_guid = scd["guid"]

print(green(f"Secure Endpoint SCD List ID : {amp_scd_guid}"))
status = amp_scd("post", amp_scd_guid, threatgrid_sha)
print(status)