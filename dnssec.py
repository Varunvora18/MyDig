# !pip install dnspython
# !pip install cryptography
import sys
import time
import socket
import datetime
from dns import message as dns_message, query as dns_query, name as dns_name
import dns.rdatatype, dns.dnssec, dns.opcode, dns.rcode, dns.flags

#This function is used to make a single iterative DNS query using dnspython
def getResponse(website,server,typeR,want_dnssec=True):
  
  query=dns.message.make_query(website,typeR,want_dnssec=True)
  response = dns.query.udp(query,server)
  
  return response

#This function is used to get the domain for the next query of DNSKEY type.   
def get_current_name(current_names):
    for current_name in current_names:
        return current_name.name

#This function is used to verify A and RRsig of A. If it is validated, the veriAflag is set to True or else throws an error
def verifyA(dns_response,dnskey_response):
  veriA = True
  try:
    dns.dnssec.validate(dns_response.answer[0],dns_response.answer[1],{dnskey_response.answer[0].name: dnskey_response.answer[0]})
    return veriA
  except :
    veriA=False
    print("A and RRSig-A are not verified, DNSSEC failed")

#This function is used to verify the DS and DS RRsig. If validated, the zone is set to True or else it throws an error.
def verifyZone(dns_response, dnskey_response) :
  zone=True
  try:
    dns.dnssec.validate(dns_response.authority[1],dns_response.authority[2],{dnskey_response.answer[0].name: dnskey_response.answer[0]})
    return zone
  except :
    zone=False
    print("Zone is not verified, DNSSEC failed")

#This function is used to verify the DNS Keys and DNSKeys RRSig. If validated, the dnskeys is set to True or else it throws an error.  
def verifyDNSKeys(dnskey_response) :
  dnskeys=True
  try:
    dns.dnssec.validate(dnskey_response.answer[0],dnskey_response.answer[1],{dnskey_response.answer[0].name: dnskey_response.answer[0]})
    return dnskeys
  except:
    dnskeys=False
    print("DNS Keys are not verified, DNSSEC failed")
  
#This functions validates the PubKSK using the DS obtained from the parent using a hashing algorithm
def verifyKSK(dnskey_response, send_to, child_ds) :
  try:
    #Getting Public Key
    for ans in dnskey_response.answer[0]:
      if ans.flags==257:
        newPublicKey = ans
        #print("New public key : ", newPublicKey)
    digest = child_ds[0].digest_type
    #print(digest)    
    hash = dns.dnssec.make_ds(send_to ,newPublicKey,digest)

    if hash == child_ds[0]:
      ksk=True
      return ksk
  except:
    ksk=False
    print("***!! KSK not verified")
    return ksk

#This handles the websites where dnssec is not supported using the NSEC3 flag
def checkNSEC(dns_response):
  for i in dns_response:
    for j in i:
      if j.rdtype==dns.rdatatype.NSEC3 or j.rdtype == dns.rdatatype.NSEC:
        return True
  return False

#This is the ultimate verification function where even if one flag is set to False, the entire DNSSEC Verification fails
def verify(dns_response,dnskey_response,child_ds=None):
  
  #Incase the dns_response has an answer, this flag handles that case.
  isEnd=False
  dnskeys=verifyDNSKeys(dnskey_response)  
  try:
    if child_ds:
      ksk=verifyKSK(dnskey_response,dnskey_response.answer[0].name,child_ds)
    else:
      ksk=True
    #print("KSK: " ,ksk)
  except:
    print("DNSSEC Verification Failed")

  if len(dns_response.answer)>0:
    veriA= verifyA(dns_response,dnskey_response)
    isEnd=True
    zone=True
    #print("veriA: " ,veriA)
    #print("isEnd: " ,isEnd)
  else:
    veriA = True
    zone=verifyZone(dns_response,dnskey_response)

  #sets the flag if all three parts are verified.
  isVerified = zone and dnskeys and ksk and veriA

  return isVerified,isEnd

#This is the recursive function that gets called after we iteratively resolve dns. 
def get_ans(website,server,typeR,next_dnskey_name,child_ds):
  
  #Stores the dns_response_query for A,NS or MX type
  dns_response=getResponse(website,server,typeR)
  
  #checks for the NSEC flag in the authority section to verify if the queried website supports DNS
  checkNSECflag = checkNSEC(dns_response.authority)
  #If it does not support, we do not move ahead and return that DNSSEC is not supported
  if checkNSECflag:
    a="DNSSEC not Supported"
    return a
  
  #This stores the dnskey response for rdatatpye -> DNSKEY
  dnskey_response=getResponse(next_dnskey_name,server,dns.rdatatype.DNSKEY)
  
  #The dns and dnskey response are sent to the verify function to validate the dnssec process. The flags are accordingly set.
  #isVerified -> checks dnssec validation
  #isEnd - > checks if we are at the final step to get the resolved IP
  isVerified,isEnd = verify(dns_response,dnskey_response,child_ds)

  #If isVerified is set to False, we do not move ahead and print that DNSSEC Verification failed.
  if not isVerified:
    print("DNSSEC Verification Failed")
    return None
  
  #If we are the final resolve, we return the answer
  if isEnd:
    return dns_response.answer
  
  try:
    #This variable stores the domain we have to use to get the next dnskey response query
    next_dnskey_name = get_current_name(dns_response.authority)
    #This variable stores the child ds which is used to verify the authenticity of the child.
    child_ds = dns_response.authority[1]
  
  except:
    return None

  #This logic has been re-used from the A part
  if len(dns_response.answer)>0:
    if "CNAME" in dns_response.answer[0].to_text():
      return dns_r(dns_response.answer[0][0].to_text(),typeR,1)
      
    return dns_response.answer
  
  elif len(dns_response.additional)>0:
    for i in range(len(dns_response.additional)):
      if "AAAA" not in dns_response.additional[i].to_text():
        check=get_ans(website,dns_response.additional[i][0].to_text(),typeR,next_dnskey_name,child_ds)
        if check:
          return check
  
  elif len(dns_response.authority)>0:
    if "SOA" in dns_response.authority[0].to_text():
      if "www" not in web:
        check = get_ans(web,server,typeR,next_dnskey_name,child_ds)
        if check:
          return check
      else:  
        return dns_response.authority[0].to_text()
    else:
      for i in dns_response.authority[0]:
        check=dns_r(i.to_text(),typeR,1)
        if check:
          if check[0].name:
            check_name=str(check[0].name).split(".")
            if "comcast" in check_name:
              a="DNSSEC Verification Failed"
              #print(a)
              return str(a)
        else:
          return check

  else:
    return None

#This is the main resolver which helps us iteratively perform the resolutions
def dns_r(website,typeR,i=0):
  if i==0:
    global web 
    web=website
  
  #List of the 13 geographically distributed servers fetched from https://www.iana.org/domains/root/servers
  root_list = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33'];
  #for root in root_list:
  root=root_list[0]

  #We first verify the root response and assume that the pubKSK received from the root is correct
  
  root_dns_response=getResponse(website,root,typeR,True)
  root_dnskey_response = getResponse(".",root,dns.rdatatype.DNSKEY,True)
  next_dnskey_name = get_current_name(root_dns_response.authority)
  ds_root = root_dns_response.authority[1]
  
  #We verify the response from Root is verified or not. If it is we get the next server from the additional section and call
  # the get_ans website to recursively resolve the query.
  isRootVerified = verify(root_dns_response,root_dnskey_response)
  for server in root_dns_response.additional:
    if server[0].rdtype == dns.rdatatype.A:
      next_server=server[0]
      break
  if isRootVerified:
    answer = get_ans(str(website),str(next_server),typeR,next_dnskey_name,ds_root)
    if answer:
        return answer

if __name__ == "__main__":
    print(dns_r(sys.argv[1],"A"))
