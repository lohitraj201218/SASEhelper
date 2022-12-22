import paramiko

HOST     = "10.192.192.3"
USERNAME = "admin"
PASSWORD = "versa123"
CMD_STARTER = ". /etc/profile.d/versa-profile.sh && "
#VSH_CONNECT_CMD      = CMD_STARTER + "vsh connect vsmd"
VSH_CONNECT_CMD  = "./versathon/getAllHistory.sh"
GET_HISTORY_BY_ID_CMD = "./versathon/getHistoryById.sh "
SHOW_HISTORY_ALL_CMD = "show saccess session history all"
SHOW_HISTORY_ID_CMD  = "show saccess session history id " 

def getRecentId(client):
    #execute command
    _stdin, _stdout,_stderr = client.exec_command(VSH_CONNECT_CMD)
    cmd_exec_str = "command executing ==> " + VSH_CONNECT_CMD
    print(cmd_exec_str)
    if _stderr != "":
        print(_stderr.read().decode())
        output = _stdout.read().decode()
        print(output)
        valueStr = output.split("Total entries : ",1)[1]
        value = int(valueStr.split("\r",1)[0])
        return value
    else:
        ''''print(_stdout.read().decode())
        return 2
        _stdin, _stdout,_stderr = client.exec_command(SHOW_HISTORY_ALL_CMD)
        if _stderr != "":
            print(_stderr.read().decode())
            return -1
        else:
            print(_stdout.read().decode())
            return 4'''

def getReport(client, startId, lastId, filename):
    reportFile = open(filename, "w")
    for i in range(startId, lastId):
        CMD_ID = SHOW_HISTORY_ID_CMD + str(i)
        _stdin, _stdout,_stderr = client.exec_command(GET_HISTORY_BY_ID_CMD + str(i))
        # _stdin.write("%r"%i)
        cmd_exec_str = "command executing ==> " + CMD_ID + "\n"
        print(cmd_exec_str)
        reportFile.write(cmd_exec_str.replace("^M", "" ))
        if _stderr != "":
            print(_stderr.read().decode())
            output = _stdout.read().decode()
            print(output)
            reportFile.write(output.replace("^M", "\n" ))
    reportFile.close()


if __name__ == "__main__":
    # connect to vos
    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USERNAME, password=PASSWORD)
    cmd_conn_str = 'connected to HOST ==> ' + HOST
    print(cmd_conn_str)
    # get recent id
    startId = getRecentId(client) - 2
    rcnt_id_str = " found recentId ==> " + str(startId)
    print(rcnt_id_str)

    lastId = getRecentId(client)
    rcnt_id_str = " found last recentId ==> " + str(lastId)
    print(rcnt_id_str)

    # generate report
    filename = "report.txt"
    getReport(client, startId, lastId, filename)
    client.close()
