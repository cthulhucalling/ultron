#!/usr/bin/python
# ULTRON Mk 1

print """
          _____
         /_____\\
    ____[\`---'/]____
   /\\ #\ \_____/ /# /\\
  /  \\# \_.---._/ #/  \\
 /   /|\\  |   |  /|\\   \\
/___/ | | |   | | | \\___\\
|  |  | | |---| | |  |  |
|__|  \\_| |_#_| |_/  |__|
//\\\\  <\\ _//^\\\\_ />  //\\\\
\\||/  |\\//// \\\\\\\\/|  \\||/
      |   |   |   |
      |---|   |---|
      |---|   |---|
      |   |   |   |
      |___|   |___|
      /   \\   /   \\
     |_____| |_____|
     |HHHHH| |HHHHH|

I have no strings to hold me down...
ULTRON Mk I
"""

#Import libraries and functions
import time
import re
from functions import attackerfile, scorefile,sendemail,elasticquery,elasticcount,by_host_historical_score,print_host_score, thirty_days, global_historical_score,flush_attackerscore
from hosts import hosts
from attacks import requestattacks,uaattacks

attackers=[]

#Logic: determine who attacked each INL host for the past 24hours or XTIMEPERIOD and build a list of IP addresses
#Perform a query with each IP address for each known attack for 7 and 30 days and tally that IP address' score

#Per host stats
for host in hosts:
        flush_attackerscore()
        print "Querying for "+host
        message=host+"\r\n"
        blnsendemail="false"
        for attack in range(len(requestattacks)):
                #print "     querying for "+requestattacks[attack][0]
                attackerip=[]
                query="{\"size\":1000,\"query\":{\"filtered\":{\"query\":{\"query_string\":{\"query\":\"host:"+host+" AND request:"+requestattacks[attack][1]+"\"}},\"filter\":{\"range\":{\"@timestamp\":{\"from\":\"now-48h\",\"to\":\"now\"}}}}}}"
                requests=elasticquery(query)
                if len(requests['hits']['hits']) > 0:
                        #print "         Got one!"
                        blnsendemail="true"
                        message+= "Attack: "+requestattacks[attack][0]+"\r\n"
                        for hit in requests['hits']['hits']:
                                message+= hit['_source']['@timestamp']+" "+hit['_source']['clientip']+" "+hit['_source']['request']+"\r\n"
                                attackerip.append(hit['_source']['clientip'])

                        uniqueattacker=list(set(attackerip))
                        uniqueattacker.sort()

                        for ip in uniqueattacker:
                                attackers.append(ip)
                                #Do historical scoring
                                by_host_historical_score(ip,host,requestattacks[attack][1],requestattacks[attack][2])

                                #Write the banlog file
                                attackerfile.write(time.strftime("%b %d %H:%M:%S")+" "+ip+"\n")
                                #Times seen in 30 days
                                i=thirty_days(ip)
                                message+= "Have seen "+ip+" "+str(i["count"])+" times in the last 30 days\r\n"
                        message+= "\r\n"

        for attack in range (len(uaattacks)):
                #print "     querying for "+uaattacks[attack][0]
                attackerip=[]
                query="{\"size\":1000,\"query\":{\"filtered\":{\"query\":{\"query_string\":{\"query\":\"host:"+host+" AND agent:"+uaattacks[attack][1]+"\"}},\"filter\":{\"range\":{\"@timestamp\":{\"from\":\"now-48h\",\"to\":\"now\"}}}}}}"
                requests=elasticquery(query)
                if len(requests['hits']['hits']) > 0:
                        #print "          Got one!"
                        blnsendemail="true"
                        message+= "Attack: "+uaattacks[attack][0]+"\r\n"
                        for hit in requests['hits']['hits']:
                                message+= hit['_source']['@timestamp']+" "+hit['_source']['clientip']+" "+hit['_source']['agent']+"\r\n"
                                attackerip.append(hit['_source']['clientip'])

                        uniqueattacker=list(set(attackerip))
                        uniqueattacker.sort()

                        for ip in uniqueattacker:
                                #Do historical scoring
                                by_host_historical_score(ip,host,requestattacks[attack][1],requestattacks[attack][2])

                                #Write the banlog file
                                attackerfile.write(time.strftime("%b %d %H:%M:%S")+" "+ip+"\n")
                                i=thirty_days(ip)
                                message+= "Have seen "+ip+" "+str(i["count"])+" times in the last 30 days\r\n"
                        message+= "\r\n"

        if blnsendemail == "true":
                #print message
                sendemail(message)
                print_host_score(host)

#Global stats across all hosts per IP
uniqueattacker=list(set(attackers))
uniqueattacker.sort()

for ip in range(len(uniqueattacker)):
        #print "Global stats for "+uniqueattacker[ip]
        #print "Attack\t\t\t\t1 hour\t24hours\t7 days\t30 days"
        #print "--------------------------------------------------------"

        scorefile.write("Global stats for "+uniqueattacker[ip]+"\r\n")
        scorefile.write("Attack\t\t\t\t1 hour\t24hours\t7 days\t30 days"+"\r\n")
        scorefile.write("--------------------------------------------------------"+"\r\n")

        for attack in range(len(requestattacks)):
                global_historical_score(uniqueattacker[ip],requestattacks[attack][0],requestattacks[attack][1],requestattacks[attack][2])

