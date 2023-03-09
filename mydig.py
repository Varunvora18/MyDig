

#!pip install dnspython
import dns.resolver
import dns.query
import dns.message
import time
import datetime
import sys

#This function is used to make a single iterative DNS query using dnspython
#Timeout if it does not resolve within 10 seconds
def getResponse(website,server,typeR):
  query=dns.message.make_query(website,typeR)
  response = dns.query.udp(query,server,timeout=10)
  return response

def get_ans(website,server,typeR):
  
  res=getResponse(website,server,typeR)
  #If the answer section is not empty, we check that section and return if there is an answer.
  #Incase of canonical names, we re-do the entire recursion again.
  if len(res.answer)>0:
    #print("In Answer")
    if "CNAME" in res.answer[0].to_text():
      #print(res.answer[0][0].to_text())
      return dns_r(res.answer[0][0].to_text(),typeR,1)
      
    return res.answer
  
  #If there is nothing in the answer section, we check the additional section 
  #for IP's of the next name servers which we can query in their hierarchy
  elif len(res.additional)>0:
    for i in range(len(res.additional)):
      #we skip the IP address if it is an IPv6 address. 
      if "AAAA" not in res.additional[i].to_text():
        check=get_ans(website,res.additional[i][0].to_text(),typeR)
        if check:
          return check
    
  #If both the answer and additional section are empty, we check the authority section to resolve the domain of authoritative name servers.
  elif len(res.authority)>0:
    if "SOA" in res.authority[0].to_text():
      if "www" not in web:
        check = get_ans(web,server,typeR)
        if check:
          return check
      else:  
        return res.authority[0].to_text()
    #When we have the name servers we re-query them from the beginning
    else:
      for i in res.authority[0]:
        check=dns_r(i.to_text(),typeR,1)
        if check:
          return check
  else:
    return None
    

def dns_r(website,typeR,i=0):

  if i==0:
    global web 
    web=website
  
  #List of the 13 geographically distributed servers fetched from https://www.iana.org/domains/root/servers
  root_list = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33'];
  for root in root_list:
    # start=time.time()
    answer=get_ans(website,root,typeR)
    if answer:
      return answer,website,typeR
  

def dig_output(domain,typeR):
    
   start=time.time()
   outp,website,typeR=dns_r(domain,typeR)
   total = time.time() - start
   date = datetime.datetime.now()
   print("Question Section")
   print(website + " IN " + typeR)
   print("ANSWER SECTION")
   print(str(outp[0]))
   #print(website + " IN " + typeR + " " + str(outp[0]))
   print("Query time " + "{:.2f}".format(total) + "s")
   print("WHEN : " , date)
   print("Message Size rcvd : " , sys.getsizeof(outp))
   
if __name__=="__main__":
    
   dig_output(sys.argv[1], sys.argv[2])
   print("")
   
   
   
    
    