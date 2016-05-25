attackerscore=[]
attackerfile=open('<path','a')
scorefile=open('<path>','w')


from elasticsearch import Elasticsearch
import smtplib

def elasticquery(query):
        es=Elasticsearch([{'host':'<elasticsearch server>','port':'9200'}])
        results=es.search(body=query,request_timeout=90)
        return results;

def elasticcount(query):
        es=Elasticsearch([{'host':'<elasticsearch server>','port':'9200'}])
        results=es.count(body=query,request_timeout=90)
        return results;

def sendemail(message):
        sender="email address"
        recipient=["email address"]
        header="""From Cthulhucalling <email address>
To: Ian Hayes <email address>
Subject: Elasticsearch report

"""
        smtpobj=smtplib.SMTP("mailhost")
        smtpobj.sendmail(sender,recipient,header+message)


def flush_attackerscore():
        del attackerscore[:]

def by_host_historical_score(ip,host,attack,score):
        attackerindex=""
        #Generate attacker 1 hour score
        query="{\"query\":{\"filtered\":{\"query\":{\"query_string\":{\"query\":\"host:"+host+" AND request:"+attack+" AND clientip:"+ip+"\"}},\"filter\":{\"range\":{\"@timestamp\":{\"from\":\"now-1h\",\"to\":\"now\"}}}}}}"
        hourscore=elasticcount(query)
        #Generate attacker 24 hour score
        query="{\"query\":{\"filtered\":{\"query\":{\"query_string\":{\"query\":\"host:"+host+" AND request:"+attack+" AND clientip:"+ip+"\"}},\"filter\":{\"range\":{\"@timestamp\":{\"from\":\"now-1d\",\"to\":\"now\"}}}}}}"
        dayscore=elasticcount(query)
        #Generate attacker 7 day score
        query="{\"query\":{\"filtered\":{\"query\":{\"query_string\":{\"query\":\"host:"+host+" AND request:"+attack+" AND clientip:"+ip+"\"}},\"filter\":{\"range\":{\"@timestamp\":{\"from\":\"now-1w\",\"to\":\"now\"}}}}}}"
        weekscore=elasticcount(query)
        #Generate attacker 30 day score
        query="{\"query\":{\"filtered\":{\"query\":{\"query_string\":{\"query\":\"host:"+host+" AND request:"+attack+" AND clientip:"+ip+"\"}},\"filter\":{\"range\":{\"@timestamp\":{\"from\":\"now-30d\",\"to\":\"now\"}}}}}}"
        monthscore=elasticcount(query)

        #Historical scoring
        for a in range(len(attackerscore)):
                if ip in attackerscore[a]:
                        attackerindex=a

        if attackerindex:
                #Copy the values out of the list
                oldhourscore=attackerscore[attackerindex][1]
                olddayscore=attackerscore[attackerindex][2]
                oldweekscore=attackerscore[attackerindex][3]
                oldmonthscore=attackerscore[attackerindex][4]
                #Reset the historical score
                del attackerscore[attackerindex]
                attackerscore.append([ip,hourscore["count"]*score+oldhourscore,dayscore["count"]*score+olddayscore,weekscore["count"]*score+oldweekscore,monthscore["count"]*score+oldmonthscore])
        else:
                attackerscore.append([ip,hourscore["count"]*score,dayscore["count"]*score,weekscore["count"]*score,monthscore["count"]*score])


def thirty_days(ip):
        query="{\"query\":{\"filtered\":{\"query\":{\"query_string\":{\"query\":\"clientip:"+ip+"\"}},\"filter\":{\"range\":{\"@timestamp\":{\"from\":\"now-30d\",\"to\":\"now\"}}}}}}"
        i=elasticcount(query)
        return i;

def print_host_score(host):
        #print host+" "+str(len(attackerscore))
        #print host+ " score"
        #print "IP address\t1 hour\t24hours\t7 days\t30 days"
        #print "--------------------------------------------------------"
        #for x in range (len(attackerscore)):
        #        print str(attackerscore[x][0])+"\t"+str(attackerscore[x][1])+"\t"+str(attackerscore[x][2])+"\t"+str(attackerscore[x][3])+"\t"+str(attackerscore[x][4])
        #print "\n\r"

        scorefile.write(host+" "+str(len(attackerscore))+"\r\n")
        scorefile.write(host+ " score"+"\r\n")
        scorefile.write("IP address\t1 hour\t24hours\t7 days\t30 days"+"\r\n")
        scorefile.write("--------------------------------------------------------"+"\r\n")
        for x in range (len(attackerscore)):
                scorefile.write(str(attackerscore[x][0])+"\t"+str(attackerscore[x][1])+"\t"+str(attackerscore[x][2])+"\t"+str(attackerscore[x][3])+"\t"+str(attackerscore[x][4])+"\r\n")
        scorefile.write("\n\r")



def global_historical_score(ip,description,attack,score):
        #1hour global
        query="{\"query\":{\"filtered\":{\"query\":{\"query_string\":{\"query\":\"clientip:"+ip+" AND request:"+attack+"\"}},\"filter\":{\"range\":{\"@timestamp\":{\"from\":\"now-1h\",\"to\":\"now\"}}}}}}"
        onehour=elasticcount(query)
        #1 day global
        query="{\"query\":{\"filtered\":{\"query\":{\"query_string\":{\"query\":\"clientip:"+ip+" AND request:"+attack+"\"}},\"filter\":{\"range\":{\"@timestamp\":{\"from\":\"now-1d\",\"to\":\"now\"}}}}}}"
        oneday=elasticcount(query)
        #7 day global
        query="{\"query\":{\"filtered\":{\"query\":{\"query_string\":{\"query\":\"clientip:"+ip+" AND request:"+attack+"\"}},\"filter\":{\"range\":{\"@timestamp\":{\"from\":\"now-1w\",\"to\":\"now\"}}}}}}"
        oneweek=elasticcount(query)
        #30 day global
        query="{\"query\":{\"filtered\":{\"query\":{\"query_string\":{\"query\":\"clientip:"+ip+" AND request:"+attack+"\"}},\"filter\":{\"range\":{\"@timestamp\":{\"from\":\"now-30d\",\"to\":\"now\"}}}}}}"
        thirtydays=elasticcount(query)

        if (thirtydays["count"]*score > 0):
                #print description+"\t\t\t\t"+str((onehour["count"])*score)+"\t"+str((oneday["count"])*score)+"\t"+str((oneweek["count"])*score)+"\t"+str((thirtydays["count"])*score)
                scorefile.write(description+"\t\t\t\t"+str((onehour["count"])*score)+"\t"+str((oneday["count"])*score)+"\t"+str((oneweek["count"])*score)+"\t"+str((thirtydays["count"])*score)+"\r\n")
