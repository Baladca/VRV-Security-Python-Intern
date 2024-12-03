import csv
from collections import defaultdict
# Configurable threshold for detecting suspicious login attempts
failedlogin_threshold = 3  

def count_requests_by_ip(log_file):
# Counts the number of requests made by each IP address
    ip_count = defaultdict(int)
    with open(log_file, 'r') as file:
        for line in file:
            ip = line.split(' ')[0]  
            ip_count[ip] += 1
    return ip_count

def find_most_accessed_endpoint(log_file):
# Finds the endpoint with the highest access count
    endpoint_count = defaultdict(int)
    with open(log_file, 'r') as file:
        for line in file:
            try:
                endpoint = line.split(' ')[3]  
                endpoint_count[endpoint] += 1
            except IndexError:
                continue  
    most_accessed = max(endpoint_count.items(), key=lambda x: x[1], default=("None", 0))
    return most_accessed

def detect_failed_logins(log_file, threshold=failedlogin_threshold):
# Identifies IPs with failed login attempts exceeding the threshold
    failed_logins_count = defaultdict(int)
    with open(log_file, 'r') as file:
        for line in file:
            if "401" in line:  
                ip = line.split(' ')[0]  
                failed_logins_count[ip] += 1
    suspicious_ips = {ip: count for ip, count in failed_logins_count.items() if count > threshold}
    return suspicious_ips

def save_analysis_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips, output_file='analysisresult.csv'):
# Saves the analysis results to a CSV file
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
# Write IP request counts        
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])
# Write the most accessed endpoint
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
 # Write suspicious IPs
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def main():
    log_file = 'sample.log' 
    ip_requests = count_requests_by_ip(log_file)
    most_accessed_endpoint = find_most_accessed_endpoint(log_file)
    suspicious_ips = detect_failed_logins(log_file)
# Display analysis results
    print("IP Address           Request Count")
    for ip, count in ip_requests.items():
        print(f"{ip:20} {count}")
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    print("\nSuspicious Activity Detected (IP Addresses with Failed Logins):")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips.items():
        print(f"{ip:20} {count}")
 # Save results to a CSV file
    save_analysis_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips)
if __name__ == '__main__':
    main()
