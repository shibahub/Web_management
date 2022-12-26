from pysnmp.entity.rfc3413.oneliner import cmdgen  
def ip_value(ip):
    print(f'Ip request IP: {ip}')
    result=[]
    errorIndication, errorStatus, errorIndex, \
    varBindTable = cmdgen.CommandGenerator().bulkCmd(  
                cmdgen.CommunityData('management'),  
                cmdgen.UdpTransportTarget((ip, 161)),  
                0, 
                25, 
                (1,3,6,1,2,1,4,21) # ipRouteTable

            )

    if errorIndication:
        print(errorIndication)
    else:
        if errorStatus:
            print (errorStatus)
                
        else:
            for varBindTableRow in varBindTable:
                for name, val in varBindTableRow:
                    tmp = name.prettyPrint()+' = '+val.prettyPrint()
                    #print(tmp)
                    result.append(tmp)
    return result

#ip_value('192.168.2.1')
