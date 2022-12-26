from pysnmp.entity.rfc3413.oneliner import cmdgen
def system_value(ip):
    result=[]
    errorIndication, errorStatus, errorIndex, varBindTable = cmdgen.CommandGenerator().nextCmd(
        cmdgen.CommunityData('management'),
        cmdgen.UdpTransportTarget((ip, 161)),
        (1,3,6,1,2,1,1)
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

#system_value('192.168.200.2')
