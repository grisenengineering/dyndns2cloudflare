from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from base64 import b64decode
from hashlib import sha256
from enum import Enum
import time
import datetime
import yaml
import os
import re
import CloudFlare

_yamlFileName = '/config/hosts.yaml'
_serverPort = 8080

class cfStatus(Enum):
    NOHOST = 0
    UPDATED = 1
    NOCHG = 2

class DDNSHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if(self.path=="/ip"):
            # This functionality returns the client IP as a simple text-string as the response (no html formating, just the text)
            # as some implementations of ddns-clients expect to be able to get it's external IP
            
            # Send a 200 response with the client ip as the response
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes("%s" % self.getOriginalClientIP(), "utf-8"))
        
        
        if(self.path.startswith('/nic/update?')):
            # DynDns2-messages consists of a GET-request formated as http://[server-fqdn]/?hostname=example.com&ip=0.0.0.0
            # username and password is sent as basic HTTP authentication

            if(not self.headers['Authorization']):
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm="Authentication required"')
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                return
            
            # The authorizaton header content is formated as "Basic [base64-encoded username:password]"
            # Try to extract header information but ignore requests with incorrectly formatted headers
            try:
                clientUserName, clientPassword = b64decode(self.headers['Authorization'].replace("Basic ","")).decode('ascii').split(":", 1)
            except:
                return

            # Parse the query-string to get the hostname and the myip parameters
            parsedQuery = parse_qs(urlparse(self.path).query)
            
            # return 400 and stop if no hostname is given
            if(not parsedQuery.get('hostname')):
                self.send_response(400)
                self.end_headers()
                self.wfile.write(bytes("nohost", "utf-8"))
                return

            clientHostName = parsedQuery.get('hostname')[0]
            
            #return 400 and stop if no ip is given
            if(not parsedQuery.get('myip')):
                self.send_response(400)
                self.end_headers()
                self.wfile.write(bytes("nohost", "utf-8"))
                return
            
            clientMyIP = parsedQuery.get('myip')[0]
            
            if(verifyDDNSRequest(clientUserName, clientPassword, clientHostName, clientMyIP, self.getOriginalClientIP())):
                
                # Set the DNS-record for the host
                print(f"[{datetime.datetime.now()}] Valid DDNS request from {clientHostName}, requested IP: {clientMyIP}")
                response = setDNS(clientHostName, clientMyIP)
                if(response == cfStatus.NOHOST):
                    # No host found in cloudflare of wrong domain, return error
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(bytes("nohost", "utf-8"))
                    return
                if(response == cfStatus.NOCHG):
                    # Host was found but already pointing to this adress, return status message
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(bytes("nochg", "utf-8"))
                    return
                
                # Host was found and update succeded, just respond witth 200 ok
                self.send_response(200)
                self.end_headers()

            else:
                # The verification for the request failed so return 403
                self.send_response(403)
                self.end_headers()
                self.wfile.write(bytes("badauth", "utf-8"))


    def getOriginalClientIP(self):
        # Returns the original client IP-adress
        # By default self.client_address[0] will return the clients IP-address as seen in the packet, 
        # If a proxy is used, headers passed by the proxy can be used instead, X-Real-IP or X-forwarded-for.
        # The proxy must be setup to present these headers

        if(os.environ.get('CLIENT_IP_SRC')):
            if (os.environ.get('CLIENT_IP_SRC').lower() == 'x-forwarded-for' and self.headers['X-forwarded-for']):
                return self.headers['X-forwarded-for']

            if (os.environ.get('CLIENT_IP_SRC').lower() == 'x-real-ip' and self.headers['X-Real-IP']):
                return self.headers['X-Real-IP']
        
        # Return the IP-adress from the TCP-packet by default
        return self.client_address[0]

def verifyDDNSRequest(clientUserName, clientPassword, clientHostName, clientIP, clientActualIP):
    # Verify that clientIP and clientHostName given by the requester are formatted correctly
    if (not re.match('^[A-Za-z][A-Za-z0-9-\.]{,63}', clientHostName)):
        return False
    if (not re.match('^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?!$)|$)){4}$', clientIP)):
        return False
    
    # Verify source IP (if set by global env vars)
    if ( os.environ.get('VERIFY_SRC_IP')!='False' and not clientIP == clientActualIP ):
        return False

    # ---------  Simple authentication  ------------
    # If simple auth is true, just compare the username and password with the ones set by the environent variables
  
    if ( os.environ.get('SIMPLE_AUTH')=='True'):
        if (clientUserName == os.environ.get('SIMPLE_HTTP_USER') and \
           (clientPassword == os.environ.get('SIMPLE_HTTP_PASSWORD') or \
            sha256(clientPassword.encode()).hexdigest().lower() == os.environ.get('SIMPLE_HTTP_PASSWORD_HASH'))):
            
            hostList = os.environ.get('SIMPLE_HOST_LIST').split(',')
            if (clientHostName in hostList):
                return True

    
    # ---------  File based authentication  ------------
    # If file authentication is active, search the hosts.yaml for the user name
    if ( os.environ.get('FILE_AUTH')=='True'):
        yamlStream = open(_yamlFileName, 'r')
        try:
            hostList = yaml.safe_load(yamlStream)
            # Run through hosts to find one with the supplied hostname and username/password
            for host in hostList:
                if(host.get('hostname')==clientHostName):
                    # Verify username and password (or password hash if no plain-text password is supplied)
                    if (clientUserName == host.get('username') and clientPassword == host.get('password')):
                        return True

                    if (clientUserName == host.get('username') and sha256(clientPassword.encode()).hexdigest().lower() == host.get('password_hash').lower()):
                        return True
        except:
            print(exc)

    return False

def setDNS(clientHostName, clientIP):
    cf = CloudFlare.CloudFlare()

    # Get the domain name by removing the subdomain from the DNS-name
    try:
        domainName = clientHostName.split('.',1)[1]
    except:
        print (f"[{datetime.datetime.now()}] WARNING: DNS-name not correctly formated. Nothing changed")
        return cfStatus.NOHOST

    # Get zone ID for the domain or return if it does not exist
    zones = cf.zones.get()
    zone_id = None
    for zone in zones:
        if clientHostName.endswith(zone['name']):
            zone_id = zone['id']

    if (not zone_id):
        print(f"[{datetime.datetime.now()}] WARNING: The CloudFlare-account does not have a zone for: {domainName}. Nothing changed")
        return cfStatus.NOHOST

    # Check if the record exists in the zone
    dns_records = cf.zones.dns_records.get(zone_id, params={'name': clientHostName})
    
    if len(dns_records) == 0:
        # Create new DNS record
        record = {
            'type': 'A',
            'name': clientHostName,
            'content': clientIP,
            'ttl': 300,
            'proxied': False
        }

        cf.zones.dns_records.post(zone_id, data=record)
        print(f"[{datetime.datetime.now()}] New DNS record created for {clientHostName} with IP address {clientIP}")
        cfStatus.UPDATED
    else:
        # Update existing DNS record
        record = dns_records[0]
        # Check if new IP matches the old IP
        if (record['content'] == clientIP):
            print(f"[{datetime.datetime.now()}] DNS record for {clientHostName} already points to {clientIP}, Nothing changed")
            return cfStatus.NOCHG
        else:
            # Change the IP-address for the record
            record['content'] = clientIP
            cf.zones.dns_records.put(zone_id, record['id'], data=record)
            print(f"[{datetime.datetime.now()}] DNS record for {clientHostName} updated with IP address {clientIP}")
            return cfStatus.UPDATED


def main():
    webServer = HTTPServer(('', _serverPort), DDNSHandler)
    print(f"[{datetime.datetime.now()}] Server started")
    webServer.serve_forever()

if __name__ == "__main__":
    main()