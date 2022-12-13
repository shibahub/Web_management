
from email import message
from http import cookies
from flask import Flask, redirect, url_for,request
from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.hlapi import *
from icmp import icmp_value
from system import system_value
from ip import ip_value
import passwd
import mysql.connector
import time 
app = Flask(__name__)
IR=[]
IE=[]
OR=[]
OE=[]
Cookie = cookies.SimpleCookie()
Cookie['IP']='127.0.0.1'


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
    response_content+=f"<Table> <tr>\
                            <th>Info.</th>\
                            <th>Description</th><tr>"
    for i in val:
                    tmp = i.split(' = ')
                    tmp2 = tmp[0].split('SNMPv2-MIB::')
                    response_content+=f'<tr><td>{tmp2[1]}</td><td>{tmp[1]}</td></tr>'
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
                                                p    {color: red;}
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
    response_content +='<table>\
                    <tr><th>Destination</th>\
                    <th>Interface</th>\
                    <th>Next hop</th>\
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
            Nex.append(tmp[1])
        if  "SNMPv2-SMI::mib-2.4.21.1.2." in  i:
            tmp = i.split(' = ')
            #print(tmp[1])
            Int.append(tmp[1])
        if  "SNMPv2-SMI::mib-2.4.21.1.7." in  i:
            tmp = i.split(' = ')
            #print(tmp[1])
            Des.append(tmp[1])
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
    response_content +='</table></HTML>'
    return response_content


@app.route('/icmp')
def ICMP():
    ip = Cookie.output().split('=')
    ip=ip[1]
    val = icmp_value(ip)
    #cur_time=time.ctime()
    response_content =''
    response_content += """<HTML>
                        <style>
                            body {background-color: white;}
                            h1   {color: Black;}
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
    response_content+=f"<Table> <tr>\
                    <th>Info.</th>\
                    <th>count</th><tr>"
    global IE
    global OE
    global IR
    global OR
    mycursor = mydb.cursor()
    mycursor.execute('USE net_man;')
    for i in val:
        tmp = i.split(' = ')
        tmp2 = tmp[0].split('SNMPv2-SMI::mib-')
        if "2.5.8.0" in i :
            response_content+=f'<tr><td>ICMPInEchos ({tmp2[1]})</td><td>{tmp[1]}</td></tr>'
            #sql = "INSERT INTO Echo_icmp (name, amount) VALUES (%s, %s)"
            #mycursor.execute(sql, (tmp2[1],tmp[1]))
        if "2.5.9.0" in i :
            response_content+=f'<tr><td>ICMPInEchosReps ({tmp2[1]})</td><td>{tmp[1]}</td></tr>'
            #sql = "INSERT INTO Echo_icmp (name, amount) VALUES (%s, %s)"
            #mycursor.execute(sql, (tmp2[1],tmp[1]))
        if "2.5.21.0" in i :
            response_content+=f'<tr><td>ICMPOutEchos ({tmp2[1]})</td><td>{tmp[1]}</td></tr>'
            sql = "INSERT INTO Echo_icmp (ip, amount, date_time) VALUES (%s, %s, %s)"
            cur_time= time.ctime()
            mycursor.execute(sql, (ip,tmp[1],cur_time))  #### modify
        if "2.5.22.0" in i :
            response_content+=f'<tr><td>ICMPOutEchosReps ({tmp2[1]})</td><td>{tmp[1]}</td></tr>'
            #sql = "INSERT INTO Echo_icmp (name, amount) VALUES (%s, %s)"
            #mycursor.execute(sql, (tmp2[1],tmp[1]))
    mycursor.execute('Select * from Echo_icmp;')
    result = mycursor.fetchall()
    for i in result:
        tmp = str(i).split("'")
        if "2.5.8.0" in tmp[1] :
            IE.append(tmp[3])
        elif "2.5.9.0" in i :
            IR.append(tmp[3])
        elif "2.5.21.0" in i :
            OE.append(tmp[3])
        elif "2.5.22.0" in i :
            OR.append(tmp[3])  
    ###plot garph###
    response_content+="</div>"
    response_content+="""<script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>
                        <script type="text/javascript">
                        google.charts.load('current', {'packages':['corechart']});
                        google.charts.setOnLoadCallback(drawChart);

                        function drawChart() {
                            var data = google.visualization.arrayToDataTable([
                            ['Year', 'Sales', 'Expenses'],
                            ['2004',  1000,      400],
                            ['2005',  1170,      460],
                            ['2006',  660,       1120],
                            ['2007',  1030,      540]
                            ]);

                            var options = {
                            title: 'Company Performance',
                            curveType: 'function',
                            legend: { position: 'bottom' }
                            };

                            var chart = new google.visualization.LineChart(document.getElementById('curve_chart'));

                            chart.draw(data, options);
                        }
                        </script>
    """
    response_content+=' <div id="curve_chart" style="width: 900px; height: 500px"></div>'
    response_content+="</HTML>"
    return response_content


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080)
