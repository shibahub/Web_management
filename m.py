from email import message
from http import cookies
from operator import sub
from re import X
from flask import Flask, redirect, url_for,request
from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.hlapi import *
from icmp import icmp_value
from system import system_value
from ip import ip_value
import mysql.connector
import time 
import passwd
from datetime import datetime

#126 ber p net man
app = Flask(__name__)

IR=[]
IE=[]
OR=[]
OE=[]
Cookie = cookies.SimpleCookie()
Cookie['IP']='127.0.0.1'

count =1
tmp_ip='127.0.0.1'
###### SQL CONNECTION #######
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password=passwd.x,
  database = 'net_man'
)
###### SQL CONNECTION #######

@app.route('/setcookie',methods = ['POST', 'GET'])
def setcookie():
    if request.method == 'POST':
        IP = request.form['IP']
        Cookie['IP']= IP   
        print(Cookie.output())
    return redirect('/')
@app.route('/')
def home():
    message = """<HTML>
                <style>
                    body {background-color: #dddddd;}
                    h1   {color: Red;}
                    p    {color: green;}
                </style>
                <H1>Network Management Web application Base</H1>
                <form action = "/setcookie" method = "POST">
                <label ="IP"  >Insert IP:</label>
                <input type="text" id="IP" name="IP" value="127.0.0.1"> 
                <input type="submit" value="Submit" action=''><br>
            </form>"""
    ip = Cookie.output().split('=')
    ip=ip[1]
    #print(ip)
    global tmp_ip
    global count
    if ip != tmp_ip:
        count+=1
        tmp_ip=ip
    message+= f'<p>Current time: {time.ctime()}</p><p>Current IP: {ip}</p>'
    message+="""<h2>System Infomation</h2>
            <button type="button"><a href="/system">System</a></button>
            <h2>IP route table</h2>
            <button type="button"><a href="/ip">IP</a></button>
            <h2>IP ICMP</h2>
            <button type="button"><a href="/icmp">ICMP</a></button>
            </HTML>"""
        
    return message



@app.route('/system',methods=['GET', 'POST'])
def system():
    ip = Cookie.output().split('=')
    ip=ip[1]
    val = system_value(ip)
    response_content =''
    response_content += """<HTML>
                            <style>
                                body {background-color: white;}
                                h1   {color: Black;}
                                p {color: green;}
                                table {
                                    font-family: arial, sans-serif;
                                    border-collapse: collapse;
                                    width: 100%;
                                }
                                td, th {
                                    border: 1px solid #dddddd;
                                    text-align: left;
                                    padding: 8px;
                                }
                                th{
                                    background-color: pink;
                                }
                                tr:nth-child(even) {
                                    background-color: pink;
                                }
                            </style>
                            <h1>System information</h1>"""
    response_content+=f'<p>IP: {ip}</p>'
    response_content+=f"<Table> <tr>\
                            <th>Info.</th>\
                            <th>Description</th><tr>"
    for i in val:
                    tmp = i.split(' = ')
                    tmp2 = tmp[0].split('SNMPv2-MIB::')
                    response_content+=f'<tr><td>{tmp2[1]}</td><td>{tmp[1]}</td></tr>'
                    #store in DB
                    mycursor = mydb.cursor()
                    mycursor.execute('USE net_man;')
                    sql = "INSERT INTO System_info (ip, OID, INFO, times) VALUES (%s, %s, %s, %s)"
                    times = time.ctime()
                    mycursor.execute(sql, (ip,tmp2[1], tmp[1], times))  #### modify
                    mydb.commit()
                    #mycursor.execute('Select * from Icmp;')
    response_content+="</HTML>"
    # END SNMP
    return response_content


@app.route('/ip')
def IP_table():
    ip = Cookie.output().split('=')
    ip=ip[1]
    val = ip_value(ip)
    response_content=''
    response_content += """<HTML>
                                            <style>
                                                body {background-color: white;}
                                                h1   {color: Black;}
                                                p    {color: green;}
                                                table {
                                                    font-family: arial, sans-serif;
                                                    border-collapse: collapse;
                                                    width: 100%;
                                                    }
                                                td, th {
                                                    border: 1px solid #dddddd;
                                                    text-align: left;
                                                    padding: 8px;
                                                    }
                                                tr:nth-child(odd) {
                                                    background-color: #dddddd;
                                                    }
                                            </style>
                                    <H1>IP ROUTE TABLE</H1>"""
    response_content+=f'<p>IP: {ip}</p>'
    response_content +='<table>\
                    <tr><th>Next hop</th>\
                    <th>Interface</th>\
                    <th>Destination</th>\
                    <th>Routing types</th>\
                    <th>Routing Protocol</th>\
                    <th>Subnet mask</th></tr>'
    Des=[] # destination
    Int=[] # interface
    Nex=[] # next hop
    Typ=[] # type 
    Pro=[] # protocol
    Bro=[] # Broad cast

    for i in val:
        test=i.split(' = ')
        if  "SNMPv2-SMI::mib-2.4.21.1.1." in  i:
            tmp = i.split(' = ')
            #print(tmp[1])
            Des.append(tmp[1])
        if  "SNMPv2-SMI::mib-2.4.21.1.2." in  i:
            tmp = i.split(' = ')
            #print(tmp[1])
            Int.append(tmp[1])
        if  "SNMPv2-SMI::mib-2.4.21.1.7." in  i:
            tmp = i.split(' = ')
            #print(tmp[1])
            Nex.append(tmp[1])
        if  "SNMPv2-SMI::mib-2.4.21.1.8." in  i:
            tmp = i.split(' = ')
            #print(tmp[1])
            Typ.append(tmp[1])
        if  "SNMPv2-SMI::mib-2.4.21.1.9." in  i:
            tmp = i.split(' = ')
            #print(tmp[1])
            Pro.append(tmp[1])
        if  "SNMPv2-SMI::mib-2.4.21.1.11." in  i:
            tmp = i.split(' = ')
            #print(tmp[1])
            Bro.append(tmp[1])
            #tmp= i.split(' = ')
    for i in range (len(Des)):
        response_content += f'<tr><td>{Des[i]}</td><td>{Int[i]}</td><td>{Nex[i]}</td><td>{Typ[i]}</td><td>{Pro[i]}</td><td>{Bro[i]}</td></tr>'                       
        #store in DB
        mycursor = mydb.cursor()
        mycursor.execute('USE net_man;')
        sql = "INSERT INTO IP_table (ip, nexthop, destination, subnet, times) VALUES (%s, %s, %s, %s, %s)"
        times = time.ctime()
        mycursor.execute(sql, (ip, Nex[i], Des[i], Bro[i], times))  #### modify
        mydb.commit()
        #mycursor.execute('Select * from Icmp;')
    response_content +='</table></HTML>'
    return response_content


@app.route('/icmp')
def ICMP():
    ip = Cookie.output().split('=')
    ip=ip[1]
    val = icmp_value(ip)

    icmp_In_Echo = val[0].split('=')
    icmp_In_Echo = (icmp_In_Echo[1])

    icmp_In_Echo_Rep = val[1].split(' =')
    icmp_In_Echo_Rep = (icmp_In_Echo_Rep[1])

    icmp_Out_Echo = val[2].split(' =')
    icmp_Out_Echo = (icmp_Out_Echo[1])

    icmp_Out_Echo_Rep = val[3].split(' =')
    icmp_Out_Echo_Rep = (icmp_Out_Echo_Rep[1])

    

    response_content =''
    response_content += """<HTML>
                        <style>
                            body {background-color: white;}
                            h1   {color: Black;}
                            p {color: green;}
                            table {
                                font-family: arial, sans-serif;
                                border-collapse: collapse;
                                width: 100%;
                           }
                            td, th {
                                border: 1px solid #dddddd;
                                text-align: left;
                                padding: 8px;
                            }
                            th{
                                background-color: skyblue;
                            }
                            tr:nth-child(even) {
                                background-color: skyblue;
                            }
                        </style>
                        <h1>ICMP Echo</h1>"""
    response_content+=f'<p>IP: {ip}</p>'
    response_content+=f"<Table> <tr>\
                    <th>Info.</th>\
                    <th>count</th><tr>"
    global IE
    global OE
    global IR
    global OR
    mycursor = mydb.cursor()
    mycursor.execute('USE net_man;')
    #############################################################################################################
    sql = "INSERT INTO Icmp (ip, icmp_in, icmp_in_rep, icmp_out, icmp_out_rep, times) VALUES (%s, %s, %s, %s, %s, %s)"
    x = time.ctime()
    #x = x.strftime("%X")
    mycursor.execute(sql, (ip,icmp_In_Echo, icmp_In_Echo_Rep, icmp_Out_Echo, icmp_Out_Echo_Rep, x))  #### modify
    mydb.commit()
    mycursor.execute('Select * from Icmp;')
    result = mycursor.fetchall()
    
    plot = []
    icmp_out = []
    plot.append("Time")
    plot.append("ICMP_In_Echo")
    plot.append("ICMP_In_Echo_Rep")
    plot.append("ICMP_Out_Echo")
    plot.append("ICMP_Out_Echo_Rep")
    icmp_out.append(plot)
    plot = []

    for i in result:
        plot.append(i[5])
        plot.append(int(i[1]))
        plot.append(int(i[2]))
        plot.append(int(i[3]))
        plot.append(int(i[4]))
        icmp_out.append(plot)
        plot = []

    response_content+=f'<tr><td>ICMP In Echo (2.5.8.0)</td><td>{icmp_In_Echo}</td></tr>'
    response_content+=f'<tr><td>ICMP In Echo Rep (2.5.9.0)</td><td>{icmp_In_Echo_Rep}</td></tr>'
    response_content+=f'<tr><td>ICMP Out Echo (2.5.21.0)</td><td>{icmp_Out_Echo}</td></tr>'
    response_content+=f'<tr><td>ICMP Out Echo Rep (2.5.22.0)</td><td>{icmp_Out_Echo_Rep}</td></tr>'

    ###plot garph###
    response_content+="</div>"
    response_content+="""<meta http-equiv="refresh" content="15">
                        <script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>
                        <script type="text/javascript">
                        google.charts.load('current', {'packages':['corechart']});
                        google.charts.setOnLoadCallback(drawChart);
                        function drawChart() {"""
    response_content+=f"""var data = google.visualization.arrayToDataTable({icmp_out});"""

    response_content+="""var options = {
                            title: 'ICMP Chart',
                            hAxis: {title: 'icmp'},                           
                            vAxis: {title: 'Time'},
                            curveType: 'function',
                            legend: { position: 'bottom' }
                            };
                            var chart = new google.visualization.LineChart(document.getElementById('curve_chart'));
                            chart.draw(data, options);
                        }
                        </script>"""

    response_content+=' <div id="curve_chart" style="width: 1500px; height: 500px"></div>'
    response_content+="</HTML>"
    #print(response_content)
    return response_content


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080)
