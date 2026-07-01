"""
Port-to-service database with risk classification.
"""
from typing import Dict, Any

# ──────────────────────────────────────────────
# Common ports profile (used with -p common)
# ──────────────────────────────────────────────
COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88,
    110, 111, 119, 123, 135, 137, 138, 139, 143, 161, 162, 179,
    389, 443, 445, 465, 500, 514, 515, 587, 631, 636, 873, 902,
    993, 995, 1080, 1194, 1433, 1521, 1723, 2049, 2082, 2083,
    2086, 2087, 3000, 3306, 3389, 3690, 4444, 4500,
    5432, 5900, 5901, 6379, 6443, 7001,
    8000, 8008, 8080, 8081, 8443, 8888,
    9000, 9090, 9200, 9300, 10000, 27017, 27018,
]

# ──────────────────────────────────────────────
# Full service registry
# ──────────────────────────────────────────────
PORT_SERVICES: Dict[int, Dict[str, Any]] = {
    20:    {"name": "FTP-DATA",       "description": "FTP Data Transfer",                "category": "File Transfer"},
    21:    {"name": "FTP",            "description": "File Transfer Protocol",            "category": "File Transfer"},
    22:    {"name": "SSH",            "description": "Secure Shell",                      "category": "Remote Access"},
    23:    {"name": "Telnet",         "description": "Unencrypted remote login",           "category": "Remote Access"},
    25:    {"name": "SMTP",           "description": "Simple Mail Transfer Protocol",      "category": "Email"},
    53:    {"name": "DNS",            "description": "Domain Name System",                 "category": "Network"},
    67:    {"name": "DHCP-Server",    "description": "DHCP Server",                       "category": "Network"},
    68:    {"name": "DHCP-Client",    "description": "DHCP Client",                       "category": "Network"},
    69:    {"name": "TFTP",           "description": "Trivial File Transfer Protocol",     "category": "File Transfer"},
    80:    {"name": "HTTP",           "description": "Hypertext Transfer Protocol",        "category": "Web"},
    88:    {"name": "Kerberos",       "description": "Network Authentication Protocol",    "category": "Security"},
    110:   {"name": "POP3",           "description": "Post Office Protocol v3",            "category": "Email"},
    111:   {"name": "RPC",            "description": "Remote Procedure Call",              "category": "Network"},
    119:   {"name": "NNTP",           "description": "Network News Transfer Protocol",     "category": "Network"},
    123:   {"name": "NTP",            "description": "Network Time Protocol",              "category": "Network"},
    135:   {"name": "MSRPC",          "description": "Microsoft RPC Endpoint Mapper",      "category": "Windows"},
    137:   {"name": "NetBIOS-NS",     "description": "NetBIOS Name Service",              "category": "Windows"},
    138:   {"name": "NetBIOS-DGM",    "description": "NetBIOS Datagram Service",          "category": "Windows"},
    139:   {"name": "NetBIOS-SSN",    "description": "NetBIOS Session Service",           "category": "Windows"},
    143:   {"name": "IMAP",           "description": "Internet Message Access Protocol",   "category": "Email"},
    161:   {"name": "SNMP",           "description": "Simple Network Management Protocol", "category": "Network"},
    162:   {"name": "SNMP-TRAP",      "description": "SNMP Trap",                         "category": "Network"},
    179:   {"name": "BGP",            "description": "Border Gateway Protocol",            "category": "Routing"},
    389:   {"name": "LDAP",           "description": "Lightweight Directory Access",       "category": "Directory"},
    443:   {"name": "HTTPS",          "description": "HTTP over TLS/SSL",                  "category": "Web"},
    445:   {"name": "SMB",            "description": "Server Message Block",               "category": "Windows"},
    465:   {"name": "SMTPS",          "description": "SMTP over SSL",                     "category": "Email"},
    500:   {"name": "IKE",            "description": "Internet Key Exchange (VPN)",        "category": "VPN"},
    514:   {"name": "Syslog",         "description": "System Logging Protocol",            "category": "Logging"},
    515:   {"name": "LPD",            "description": "Line Printer Daemon",                "category": "Printing"},
    587:   {"name": "SMTP-Sub",       "description": "SMTP Submission Port",               "category": "Email"},
    631:   {"name": "IPP",            "description": "Internet Printing Protocol",         "category": "Printing"},
    636:   {"name": "LDAPS",          "description": "LDAP over SSL",                     "category": "Directory"},
    873:   {"name": "rsync",          "description": "Remote File Synchronization",        "category": "File Transfer"},
    902:   {"name": "VMware",         "description": "VMware ESXi/Server",                "category": "Virtualization"},
    993:   {"name": "IMAPS",          "description": "IMAP over SSL",                     "category": "Email"},
    995:   {"name": "POP3S",          "description": "POP3 over SSL",                     "category": "Email"},
    1080:  {"name": "SOCKS",          "description": "SOCKS Proxy Protocol",               "category": "Proxy"},
    1194:  {"name": "OpenVPN",        "description": "OpenVPN",                            "category": "VPN"},
    1433:  {"name": "MSSQL",          "description": "Microsoft SQL Server",               "category": "Database"},
    1521:  {"name": "Oracle-DB",      "description": "Oracle Database Listener",           "category": "Database"},
    1723:  {"name": "PPTP",           "description": "Point-to-Point Tunneling VPN",       "category": "VPN"},
    2049:  {"name": "NFS",            "description": "Network File System",                "category": "File Share"},
    2082:  {"name": "cPanel",         "description": "cPanel Web Hosting Control",         "category": "Web Admin"},
    2083:  {"name": "cPanel-SSL",     "description": "cPanel over SSL",                   "category": "Web Admin"},
    2086:  {"name": "WHM",            "description": "WHM Web Host Manager",               "category": "Web Admin"},
    2087:  {"name": "WHM-SSL",        "description": "WHM over SSL",                      "category": "Web Admin"},
    3000:  {"name": "Dev-Server",     "description": "Development / Node.js Server",       "category": "Web"},
    3306:  {"name": "MySQL",          "description": "MySQL Database Server",              "category": "Database"},
    3389:  {"name": "RDP",            "description": "Remote Desktop Protocol",            "category": "Remote Access"},
    3690:  {"name": "SVN",            "description": "Apache Subversion",                  "category": "Version Control"},
    4444:  {"name": "Metasploit",     "description": "Metasploit default handler",         "category": "Security"},
    4500:  {"name": "IKE-NAT",        "description": "IKE NAT Traversal",                 "category": "VPN"},
    5432:  {"name": "PostgreSQL",     "description": "PostgreSQL Database Server",         "category": "Database"},
    5900:  {"name": "VNC",            "description": "Virtual Network Computing",          "category": "Remote Access"},
    5901:  {"name": "VNC-1",          "description": "VNC Display 1",                     "category": "Remote Access"},
    6379:  {"name": "Redis",          "description": "Redis In-Memory Data Store",         "category": "Database"},
    6443:  {"name": "Kubernetes",     "description": "Kubernetes API Server",              "category": "Container"},
    7001:  {"name": "WebLogic",       "description": "Oracle WebLogic Server",             "category": "App Server"},
    8000:  {"name": "HTTP-Alt",       "description": "Alternative HTTP",                   "category": "Web"},
    8008:  {"name": "HTTP-Alt2",      "description": "Alternative HTTP",                   "category": "Web"},
    8080:  {"name": "HTTP-Proxy",     "description": "HTTP Proxy / Alternate HTTP",        "category": "Web"},
    8081:  {"name": "HTTP-Alt3",      "description": "Alternative HTTP",                   "category": "Web"},
    8443:  {"name": "HTTPS-Alt",      "description": "Alternate HTTPS",                    "category": "Web"},
    8888:  {"name": "Jupyter",        "description": "Jupyter Notebook Server",             "category": "Development"},
    9000:  {"name": "PHP-FPM",        "description": "PHP FastCGI / SonarQube",            "category": "Web"},
    9090:  {"name": "Prometheus",     "description": "Prometheus Metrics",                 "category": "Monitoring"},
    9200:  {"name": "Elasticsearch",  "description": "Elasticsearch HTTP API",             "category": "Database"},
    9300:  {"name": "ES-Transport",   "description": "Elasticsearch Transport",            "category": "Database"},
    10000: {"name": "Webmin",         "description": "Webmin Admin Panel",                 "category": "Web Admin"},
    27017: {"name": "MongoDB",        "description": "MongoDB Database Server",            "category": "Database"},
    27018: {"name": "MongoDB-Alt",    "description": "MongoDB Alternate Port",             "category": "Database"},
}

# ──────────────────────────────────────────────
# Risk classification
# ──────────────────────────────────────────────
HIGH_RISK_PORTS = {
    21, 23, 69, 111, 135, 137, 138, 139,
    445, 1433, 1521, 3306, 3389, 4444, 5900, 5901,
    6379, 9200, 27017, 27018,
}

MEDIUM_RISK_PORTS = {
    22, 25, 80, 161, 389, 873, 902, 1080,
    2082, 2083, 2086, 2087, 5432, 7001, 8080, 8443, 10000,
}


def get_service_info(port: int) -> Dict[str, Any]:
    """Return service info dict for a given port number."""
    if port in PORT_SERVICES:
        info = PORT_SERVICES[port].copy()
    else:
        info = {
            "name":        "Unknown",
            "description": f"Unregistered service on port {port}",
            "category":    "Unknown",
        }

    if port in HIGH_RISK_PORTS:
        info["risk"] = "HIGH"
    elif port in MEDIUM_RISK_PORTS:
        info["risk"] = "MEDIUM"
    else:
        info["risk"] = "LOW"

    return info
