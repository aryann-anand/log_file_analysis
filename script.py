from collections import defaultdict, Counter
from collections import Counter
import csv
import re
import os

# log file path
log_file = 'sample.log'

# regex to extract from log file
ip_regex = r'(\d+\.\d+\.\d+\.\d+)'
endpoint_regex = r'\"[A-Z]+\s(\/\S*)\s'
status_code_regex = r'\"\s(\d{3})\s'
failed_login_message = 'Invalid credentials'

# dict to store results
ip_requests = defaultdict(int)
endpoint_access = defaultdict(int)
failed_logins = defaultdict(int)

# set threshold for max login attempts
login_max = 10

# parse the log file

with open(log_file, 'r') as file:
    for line in file:

        # extracting IP address

        ip_match = re.search(ip_regex, line)
        if ip_match:
            ip = ip_match.group(1)
            ip_requests[ip] += 1
        
        # extract endpoint
        
        endpoint_match = re.search(endpoint_regex, line)
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            endpoint_access[endpoint] += 1
        
        # check for failed login attempts (with 401 error or Invalid Credentials error)

        status_code_match = re.search(status_code_regex, line)
        if status_code_match and status_code_match.group(1) == '401':
            if failed_login_message in line:
                failed_logins[ip] += 1

# sort IP addresses by req count
sorted_ip_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)

# analyze the max requested endpoint
most_accessed_endpoint, access_count = max(endpoint_access.items(), key=lambda x: x[1])

# identify the failed login attempts
suspicious_activity = {ip: count for ip, count in failed_logins.items() if count > login_max}

print("\nRequests per IP Address:")
print(f"{'IP Address':<20} {'Request Count':<15}")

for ip, count in sorted_ip_requests:
    print(f"{ip:<20} {count:<15}")

print("\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed_endpoint} (Accessed {access_count} times)")

if suspicious_activity:
    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts':<20}")

    for ip, count in suspicious_activity.items():
        print(f"{ip:<20} {count:<20}")
else:
    print("\nNo suspicious activity detected.")

# saved results to csv
with open('log_analysis_results.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    
    # requests per IP -> write to csv
    writer.writerow(['Requests per IP'])
    writer.writerow(['IP Address', 'Request Count'])
    for ip, count in sorted_ip_requests:
        writer.writerow([ip, count])
    
    # most accessed endpoint
    writer.writerow([])
    writer.writerow(['Most Frequently Accessed Endpoint:'])
    writer.writerow(['Endpoint', 'Access Count'])
    writer.writerow([most_accessed_endpoint, access_count])
    
    # sus activity if any
    writer.writerow([])
    writer.writerow(['Suspicious Activity Detected:'])
    writer.writerow(['IP Address', 'Failed Login Attempts'])
    for ip, count in suspicious_activity.items():
        writer.writerow([ip, count])

print("\n Analysis Complete! \nResults saved to csv.")
