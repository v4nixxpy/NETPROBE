import re,time,dns.resolver,socket,threading
import requests,bs4,ssl
from colorama import Fore,Style
from cryptography import x509
from cryptography.hazmat.primitives import serialization
#Banner : 
print(Fore.CYAN + """
███╗   ██╗███████╗████████╗██████╗ ██████╗  ██████╗ ██████╗ ███████╗
████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
██╔██╗ ██║█████╗     ██║   ██████╔╝██████╔╝██║   ██║██████╔╝█████╗  
██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝  
██║ ╚████║███████╗   ██║   ██║     ██║  ██║╚██████╔╝██████╔╝███████╗
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
""" + Style.RESET_ALL)

#Main Objects:
dnsReslover= dns.resolver
threads = []
lock = threading.Lock()
context = ssl.create_default_context()
# Main Methods For Netwrok Racon:
def points(number):
  for i in range(number):
    print(Fore.RED + "."+Style.RESET_ALL,end="")
    time.sleep(0.2)
  print("\n",end="")
def is_domain_exists(domain):
  try:
    result = dns.resolver.resolve(domain,"A")
    if result :
      return True
  except dns.resolver.NXDOMAIN:
    return False
def dns_lookup(domain):
  try:
    Arecord = dnsReslover.resolve(domain,"A")
    MXrecord = dnsReslover.resolve(domain,"MX")
    NSrecord = dnsReslover.resolve(domain,"NS")
    return Arecord,MXrecord,NSrecord
  except dnsReslover.NoAnswer:
    print(f"No Record in This Domain")
  except dnsReslover.NXDOMAIN :
    print(f"Domain is Not Exists")
def port_scan(target,port):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.settimeout(3)
    result = sock.connect_ex((target,port))
    sock.close()
    with lock:
      if result == 0 : 
        print(Fore.GREEN +f"    -Port {port} Open"+ Style.RESET_ALL)
      else:
        print(Fore.LIGHTRED_EX +f"    -Port {port} Closed"+ Style.RESET_ALL)
def http_headers(url):
  try:
    response = requests.get(url,timeout=3)
    soupe = bs4.BeautifulSoup(response.text,"lxml")
    title = soupe.find("title").text
    return response,title
  except requests.exceptions.RequestException:
      return False
def ssl_info(domain):
  try:
    with socket.create_connection((domain,443)) as sock :
      with context.wrap_socket(sock,server_hostname=domain) as sscok :
        cert = sscok.getpeercert()
        binary_cert = sscok.getpeercert(binary_form=True)
        return cert,binary_cert
  except ssl.SSLError:
    return False
  except socket.timeout:
    return False
  except socket.gaierror:
    return False
  except ConnectionRefusedError:
    return False


# Get The Input From The User : 
pattern = re.compile(r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
while True :
  Domain = input("Enter Domain To Scan :").strip()
  if not re.match(pattern,Domain):
    print(Fore.RED + f"Invalid Domain Name Try Again!"+ Style.RESET_ALL,end="")
    points(3)
  elif not is_domain_exists(Domain):
    print(Fore.RED + f"Domain is Not Exists,Try With Another Domain" + Style.RESET_ALL,end="")
    points(3)
  else:
    break

while True:
  Ports_input = input("Enter Ports To Scan (Comma Separated): ").strip()
  port_list = Ports_input.split(",")
  if all(p.strip().isdigit() and 1 <= int(p.strip()) <= 65535 for p in port_list):
    Ports =[int(p.strip()) for p in port_list]
    break
  else:
    print(Fore.RED + "Invalid Ports! Try Again!" + Style.RESET_ALL,end="")
    points(3)


print("Network Recon".center(50,"="))
#Print Results :
  #TODO : Print Ports Status:
print(f" | {'Port Scanning':<8} : ")
for port in Ports:
  t= threading.Thread(target=port_scan,args=(Domain,port))
  t.start()
  threads.append(t)
for t  in threads:
  t.join()
  #TODO : Print Records:
print(f" | {'Dns LookUP':<8} : ")
Arecord, Mxrecord , NSrecord = dns_lookup(Domain)
print(Fore.CYAN + f"    -A Record" + Style.RESET_ALL)
for r in Arecord:
  print(f"      *{"Ip":<8}:{Fore.CYAN + str(r)+Style.RESET_ALL}")
print(Fore.CYAN +f"    -MX Record"+ Style.RESET_ALL)
for r in Mxrecord:
  exchange = r.exchange
  prefrence = r.preference
  print(f"      *{"Server":8}:{Fore.CYAN + str(exchange)+Style.RESET_ALL}")
  print(f"      *{"Preference":<8}:{Fore.CYAN + str(prefrence)+Style.RESET_ALL}")
  print(f"       ----------------")
print(Fore.CYAN +f"    -NS Record"+ Style.RESET_ALL)
for r in NSrecord:
  print(f"      *{"Server":<8}: {Fore.CYAN + str(r) +Style.RESET_ALL}")
  #TODO : Print Headers:
print(f" | {'HTPP Headers':<8} : ")
response,title = http_headers(f"https://{Domain}")
if response:
  headers = response.headers
  server = headers.get("Server","N/A")
  Content_Type =  headers.get("Content-Type","N/A")
  x_frame_options =  headers.get("X-Frame-Options","N/A")
  set_cookie = headers.get("Set-Cookie","N/A")
  x_powerd_by = headers.get("X-Powered-By","N/A")
  strict__Security = headers.get("Strict-Transport-Security","N/A")
  print(f"      *{Fore.CYAN + "Website Title":<10}{Style.RESET_ALL} : {title}")
  print(f"      *{Fore.CYAN + "Server":<10}{Style.RESET_ALL} : {server}")
  print(f"      *{Fore.CYAN + "X-Powered-By":<10}{Style.RESET_ALL} : {x_powerd_by}")
  print(f"      *{Fore.CYAN + "Content-Type":<10}{Style.RESET_ALL} : {Content_Type}")
  print(f"      *{Fore.CYAN + "Strict-Transport-Security":<10}{Style.RESET_ALL} : {strict__Security}")
  print(f"      *{Fore.CYAN + "X-Frame-Options":<10}{Style.RESET_ALL} : {x_frame_options}")
  print(f"      *{Fore.CYAN + "Set-Cookie":<10}{Style.RESET_ALL} : {set_cookie[:100]}")
  #TODO : Print SSL Certificates:
print(f" | {'SSL Certificates':<8} : ")
cert,binary_cert = ssl_info(Domain)
if cert :
  cert_obj = x509.load_der_x509_certificate(binary_cert)
  public_key = cert_obj.public_key()
  public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
  )
  lines = public_key_pem.decode().strip().split("\n")
  public_key_only = "".join(lines[1:-1])
  subject = cert["subject"][0][0][1]
  issuer = cert['issuer'][1][0][1]
  certAfter = cert["notAfter"]
  certBefor = cert['notBefore']
  
  print(f"      *{Fore.CYAN + "Public Key":<10}{Style.RESET_ALL} : {public_key_only}")
  print(f"      *{Fore.CYAN + "Subject":<10}{Style.RESET_ALL} : {subject}")
  print(f"      *{Fore.CYAN + "issuer":<10}{Style.RESET_ALL} : {issuer}")
  print(f"      *{Fore.CYAN + "notBefore":<10}{Style.RESET_ALL} : {certBefor}")
  print(f"      *{Fore.CYAN + "notAfter":<10}{Style.RESET_ALL} : {certAfter}")