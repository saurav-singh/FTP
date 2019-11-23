# ------------------------------------------------------------------------------------------
# Imports
# ------------------------------------------------------------------------------------------
import socket
import sys
from ftp_logger import Logger

BUFFER = 5120

# ------------------------------------------------------------------------------------------
# FTP class :
# Handles all the FTP client protocols
# ------------------------------------------------------------------------------------------


class FTP:
    # --------------------------------------------------------------------------------------
    # Attributes:
    # hostToConnect - host to connect, host - our host ip,
    # socket - instance of FTPSocket class, authenticated = user login state,
    # passive - client's passive mode, dataPort - port used by data socket
    # --------------------------------------------------------------------------------------
    def __init__(self, host, ftpSocket):
        self.hostToConnect = socket.gethostbyname(host)
        self.host = socket.gethostbyname(socket.gethostname())
        self.socket = ftpSocket
        self.authenticated = False
        self.passive = False
        self.dataPort = 65000

    # --------------------------------------------------------------------------------------
    # Starts the protocol while user is in authenticated state unless connection loss occurs
    # --------------------------------------------------------------------------------------
    def startProtocol(self):

        # Authenticate user
        self.USER()

        # Run if used authenticated
        while self.authenticated:
            cmd = input("ftp> ")
            try:
                self.doAction(cmd)
            except:
                exit(0)

    # --------------------------------------------------------------------------------------
    # Performs the protcol action based on user input
    # Parameters: cmd - command entered by the user
    # --------------------------------------------------------------------------------------
    def doAction(self, cmd):

        cmd = cmd.split()
        cmdLength = len(cmd)

        commands = {
            "user": self.USER,
            "pass": self.PASS,
            "cd": self.CWD,
            "pwd": self.PWD,
            "quit": self.QUIT,
            "pasv": self.PASV,
            "epsv": self.EPSV,
            "port": self.PORT,
            "eprt": self.EPRT,
            "get": self.RETR,
            "put": self.STOR,
            "ls": self.LIST,
            "help": self.HELP,
        }

        if (cmdLength == 0 or cmd[0] not in commands):
            print("Invalid Command. Type help for available commands.\n")
            return

        func = commands.get(cmd[0])

        if (cmdLength > 1):
            try:
                arg = " ".join(cmd[1:]).replace("\"", "")
                func(arg)
            except:
                func()
        else:
            func()

    # --------------------------------------------------------------------------------------
    # Command Functions implementations for the protocol
    # --------------------------------------------------------------------------------------

    # --------------------------------------------------------------------------------------
    # user - Send username to the server
    # --------------------------------------------------------------------------------------
    def USER(self):
        cmd = "USER " + str(input("Enter username: "))
        self.socket.send(cmd)
        if not self.checkError(self.socket.recv()):
            return
        self.PASS()

    # --------------------------------------------------------------------------------------
    # pass - Send password to the server
    # --------------------------------------------------------------------------------------
    def PASS(self):
        cmd = "PASS " + str(input("Enter password: "))
        self.socket.send(cmd)
        if not self.checkError(self.socket.recv()):
            self.authenticated = False
            return
        self.authenticated = True

    # --------------------------------------------------------------------------------------
    # quit - Quit the connection and exit the program
    # --------------------------------------------------------------------------------------
    def QUIT(self):
        cmd = "QUIT"
        self.socket.send(cmd)
        print(self.socket.recv())
        exit(0)

    # --------------------------------------------------------------------------------------
    # pwd - Print current working directory
    # --------------------------------------------------------------------------------------
    def PWD(self):
        cmd = "PWD"
        self.socket.send(cmd)
        if not self.checkError(self.socket.recv()):
            return

    # --------------------------------------------------------------------------------------
    # cd path - Change working directory. path is required
    # --------------------------------------------------------------------------------------
    def CWD(self, path=None):
        if (path == None):
            path = str(input("Enter Directory: "))
        cmd = "CWD " + path
        self.socket.send(cmd)
        if not self.checkError(self.socket.recv()):
            return

    # --------------------------------------------------------------------------------------
    # port - Send an open port to the server and start listening for data (ipv4 only)
    # --------------------------------------------------------------------------------------
    def PORT(self):
        self.passive = False

        # Get an open port
        while not self.socket.checkforPort(self.host, self.dataPort):
            self.dataPort -= 2
            if self.dataPort < 5000:
                self.dataPort = 65000

        # Parse ip and port to create the command
        ip = self.host.replace('.', ',')
        p1, p2 = self.parsePort(self.dataPort)
        cmd = "PORT " + ip + "," + p1 + "," + p2

        # Send the command
        self.socket.send(cmd)

        # Retrieve the message
        if not self.checkError(self.socket.recv()):
            return

        # Listen on dataSocket
        self.socket.listenData(self.host, self.dataPort)

        # Change data Port
        self.dataPort -= 2

    # --------------------------------------------------------------------------------------
    # eprt - Send an open port to the server and start listening for data (ipv4 and ipv6)
    # --------------------------------------------------------------------------------------
    def EPRT(self):
        self.passive = False

        # Parse netPtr based on host ip type
        netPtr = " |2|" if (self.checkIPtype == "v6") else " |1|"

        # Get an open port
        while not self.socket.checkforPort(self.host, self.dataPort):
            self.dataPort -= 2
            if self.dataPort < 5000:
                self.dataPort = 65000

        # Create command
        cmd = "EPRT" + netPtr + str(self.host) + "|" + str(self.dataPort) + "|"

        # Send the command
        self.socket.send(cmd)

        # Retrieve the message
        if not self.checkError(self.socket.recv()):
            return

        # Listen on dataSocket
        self.socket.listenData(self.host, self.dataPort)

        # Change dataPort
        self.dataPort -= 2

    # --------------------------------------------------------------------------------------
    # pasv - Enable passive mode and retrieve a port from server for data transfer (ipv4 only)
    # --------------------------------------------------------------------------------------
    def PASV(self):

        # Create and Send command
        cmd = "PASV"
        self.socket.send(cmd)

        # Retrive the response
        response = self.socket.recv()
        if not self.checkError(response):
            return
        response = response[26:].replace(").", "").split(",")

        # Parse the response to get port number
        p1 = int(response[-2])
        p2 = int(response[-1])
        port = self.parsePort((p1, p2))

        # Connect dataSocket to the parsed port
        if self.socket.connectData(self.hostToConnect, port):
            self.passive = True
        else:
            return

    # --------------------------------------------------------------------------------------
    # epsv - Enable passive mode and retrive a port from server for data transfer (ipv4 and ipv6)
    # --------------------------------------------------------------------------------------
    def EPSV(self):
        # Create and send command
        cmd = "EPSV"
        self.socket.send(cmd)

        # Retrieve and parse response for port number
        response = self.socket.recv()
        if not self.checkError(response):
            return
        print(response)
        port = int(response[36:-3].replace("|", ""))

        # Connect data Socket to parsed port
        if self.socket.connectData(self.hostToConnect, port):
            self.passive = True
        else:
            return

    # --------------------------------------------------------------------------------------
    # ls [path] - List directory listing. [path] is optional
    # --------------------------------------------------------------------------------------
    def LIST(self, path=None):
        # Create command
        cmd = "LIST"
        cmd = cmd if (path == None) else cmd + " " + path

        # Connect dataSocket if already not connected
        if not self.socket.checkDataConn():
            if self.checkIPtype == "v6":
                self.EPRT()
            else:
                self.PORT()

        # Send command
        self.socket.send(cmd)

        # Retrieve the message
        if not self.checkError(self.socket.recv()):
            return

        # Retrieve and print data
        print(self.socket.acceptData(
            self.passive, True).decode("utf-8"))

        # Retrieve the message
        if not self.checkError(self.socket.recv()):
            return

    # --------------------------------------------------------------------------------------
    # get filePath - Retrieve file from the server. filePath is required.
    # --------------------------------------------------------------------------------------
    def RETR(self, path=None):
        if (path == None):
            path = str(input("Enter File Name: "))

        # Create Command
        cmd = "RETR " + path

        # Connect dataSocket if already not connected
        if not self.socket.checkDataConn():
            if self.checkIPtype == "v6":
                self.EPRT()
            else:
                self.PORT()

        # Send the command
        self.socket.send(cmd)

        # Receive the message
        if not self.checkError(self.socket.recv()):
            return

        # Receive the data
        print("Retrieving file ...\n")
        data = self.socket.acceptData(self.passive)

        # Retreive the message
        if not self.checkError(self.socket.recv()):
            return

        # Write data to the file
        try:
            F = open(path, "wb+")
            F.write(data)
            F.close()
        except:
            print("Error writing to file.\n")
            return

    # --------------------------------------------------------------------------------------
    # put filePath - Upload file to the server. filePath is required
    # --------------------------------------------------------------------------------------
    def STOR(self, path=None):
        if (path == None):
            path = str(input("Enter File Name: "))

        # Create the command
        cmd = "STOR " + path

        # Read bytes from file
        try:
            F = open(path, "rb")
            data = F.read()
            F.close()
        except:
            print("Error reading the file.\n")
            return

        # Connect dataSocket if already not connected
        if not self.socket.checkDataConn():
            if self.checkIPtype == "v6":
                self.EPRT()
            else:
                self.PORT()

        # Send the command
        self.socket.send(cmd)

        # Retrieve the message
        if not self.checkError(self.socket.recv()):
            return

        # Upload the file
        print("Uploading file ...\n")
        self.socket.sendData(data, self.passive)

        # Retrieve the message
        if not self.checkError(self.socket.recv()):
            return

    # --------------------------------------------------------------------------------------
    # help - Prints list of available commands
    # --------------------------------------------------------------------------------------
    def HELP(self):
        print("Available Commands:")
        print("-" * 40)
        print("cd \t\t eprt \t\t espv")
        print("port \t\t get \t\t ls")
        print("pass \t\t pasv \t\t put")
        print("pwd \t\t quit \t\t user\n")

    # --------------------------------------------------------------------------------------
    # Helper Functions
    # --------------------------------------------------------------------------------------

    # --------------------------------------------------------------------------------------
    # Received message from the server is sent here for error checking
    # --------------------------------------------------------------------------------------
    def checkError(self, msg):
        print(msg)
        code = int(msg[:3])

        if (code == 421):
            print("\nConnection timed out.\n")
            self.socket.closeDataConn()
            exit(0)

        if (code >= 400):
            self.socket.closeDataConn()
            return False

        return True

    # --------------------------------------------------------------------------------------
    # Parses port two ways
    # --------------------------------------------------------------------------------------
    def parsePort(self, port):
        if (isinstance(port, tuple)):
            p1, p2 = port[0], port[1]
            return int((p1 * 256) + p2)

        if (isinstance(port, int)):
            p2 = int(port % 256)
            p1 = int((port - p2) / 256)
            return str(p1), str(p2)

    # --------------------------------------------------------------------------------------
    # Check if an ip is v4 or v6
    # --------------------------------------------------------------------------------------
    def checkIPtype(self):
        if "." in self.host:
            return "v4"
        if ":" in self.host:
            return "v6"
        return None

# ------------------------------------------------------------------------------------------
# FTPSocket Classs:
# Handles socket connections and data flow for control and data socket for the client
# Also handles the logging of each messages sent and received by the client
# ------------------------------------------------------------------------------------------


class FTPSocket:
    # --------------------------------------------------------------------------------------
    # Attributes:
    # socketControl - Control socket which handles sending and receving commands
    # scoketData - Data scoket which handles sending and receivng data
    # logger - Logger which logs each message / data sent and received
    # --------------------------------------------------------------------------------------
    def __init__(self, host, port, fileName):
        self.socketControl = None
        self.socketData = None
        self.logger = Logger(fileName)
        self.connectControl(host, port)

    # --------------------------------------------------------------------------------------
    # Function - Connects control socket to the host
    # Parameters : host - host to connect, port - port to connect
    # Return : None
    # --------------------------------------------------------------------------------------
    def connectControl(self, host, port):
        host = socket.gethostbyname(host)
        af_inet = socket.AF_INET if (self.isIPV4(host)) else socket.AF_INET6
        self.socketControl = socket.socket(af_inet, socket.SOCK_STREAM)
        try:
            self.socketControl.connect((host, port))
            response = self.decode(self.socketControl.recv(1024))
            self.log("Connected to " + host + ":" + str(port), "Connection")
            self.log(response, "Received")
            print(response)
        except socket.error as E:
            print(E)
            self.log("\nConnection timed out.\n", "Received")
            exit(0)

    # --------------------------------------------------------------------------------------
    # Function - Connects data socket to the host
    # Parameters : host - host to connect, port - port to connect
    # Return : None
    # --------------------------------------------------------------------------------------
    def connectData(self, host, port):
        af_inet = socket.AF_INET if (self.isIPV4(host)) else socket.AF_INET6
        self.socketData = socket.socket(af_inet, socket.SOCK_STREAM)
        try:
            self.socketData.connect((host, port))
            return True
        except:
            self.log("\nConnection timed out.\n", "Received")
            return False

    # --------------------------------------------------------------------------------------
    # Function - Listen to data at a specified port using data socket
    # Parameters : host - Our host ip, port - port to where it needs to listen
    # Return : None
    # --------------------------------------------------------------------------------------
    def listenData(self, host, port):
        af_inet = socket.AF_INET if (self.isIPV4(host)) else socket.AF_INET6
        self.socketData = socket.socket(af_inet, socket.SOCK_STREAM)
        self.socketData.bind((host, port))
        self.socketData.listen(5)

    # --------------------------------------------------------------------------------------
    # Function - Checks if a certain port is open for a given host
    # Parameters : host - host to check, port - port to check
    # Return : True, False
    # --------------------------------------------------------------------------------------
    def checkforPort(self, host, port):
        af_inet = socket.AF_INET if (self.isIPV4(host)) else socket.AF_INET6
        testSocket = socket.socket(af_inet, socket.SOCK_STREAM)
        try:
            testSocket.bind((host, port))
            testSocket.close()
            return True
        except:
            return False

    # --------------------------------------------------------------------------------------
    # Function - Accepts data from the FTP server using data socket
    # Parameters : passive - client's passive mode, logData - True to log the data
    # Return : Data (bytes) received from the server
    # --------------------------------------------------------------------------------------
    def acceptData(self, passive, logData=False):
        if (passive):
            clientSocket = self.socketData
        else:
            clientSocket = self.socketData.accept()[0]
        data = bytearray()
        while True:
            response = clientSocket.recv(BUFFER)
            if (not response):
                break
            data.extend(response)

        self.closeDataConn()

        if (logData):
            try:
                self.log(self.decode(data), "Data")
            except:
                pass

        return data

    # --------------------------------------------------------------------------------------
    # Function - Sends data to the server using data socket
    # Parameters : data - (bytes) to be sent, passive - client's passive mode
    # Return : None
    # --------------------------------------------------------------------------------------
    def sendData(self, data, passive):
        if (passive):
            clientSocket = self.socketData
        else:
            clientSocket = self.socketData.accept()[0]

        clientSocket.send(data)
        self.closeDataConn()

    # --------------------------------------------------------------------------------------
    # Function - Closes the data socket connection
    # Parameters : None
    # Return : None
    # --------------------------------------------------------------------------------------
    def closeDataConn(self):
        if self.socketData:
            self.socketData.close()
            self.socketData = None

    # --------------------------------------------------------------------------------------
    # Function - Checkts if the data socket connection is open or not
    # Parameters : None
    # Return : True , False
    # --------------------------------------------------------------------------------------
    def checkDataConn(self):
        if self.socketData:
            return True
        return False

    # --------------------------------------------------------------------------------------
    # Function - Decodes bytes to utf-8 format
    # Parameters : val - value to decode
    # Return : decoded value
    # --------------------------------------------------------------------------------------
    def decode(self, val):
        return val.decode("utf-8")

    # --------------------------------------------------------------------------------------
    # Function - Encodes the utf-8 data into bytes
    # Parameters : val - value to encode
    # Return : encoded value
    # --------------------------------------------------------------------------------------
    def encode(self, val):
        return (val+"\r\n").encode("utf-8")

    # --------------------------------------------------------------------------------------
    # Function - Sends commands to the FTP server using control socket
    # Parameters : cmd - command to send
    # Return : None
    # --------------------------------------------------------------------------------------
    def send(self, cmd):
        self.log(cmd, "Sent")
        cmd = self.encode(cmd)
        self.socketControl.send(cmd)

    # --------------------------------------------------------------------------------------
    # Function - Receives messages from the FTP server using control socket
    # Parameters : None
    # Return : message received from the server
    # --------------------------------------------------------------------------------------
    def recv(self):
        recv = self.socketControl.recv(BUFFER)
        msg = self.decode(recv)
        self.log(msg, "Received")
        return msg

    # --------------------------------------------------------------------------------------
    # Function - Checks if a given ip is ipv4 (if not its ipv6)
    # Parameters : ip to check
    # Return : True, False
    # --------------------------------------------------------------------------------------
    def isIPV4(self, ip):
        if "." in ip:
            return True
        return False

    # --------------------------------------------------------------------------------------
    # Function - Logs messages to the log file
    # Parameters : msg - the message sent/ received, action - "Received" | "Sent"
    # Return : None
    # --------------------------------------------------------------------------------------
    def log(self, msg, action):
        self.logger.log(msg, action)


# ------------------------------------------------------------------------------------------
# Main Function : Receives 2 - 3 arguments and executes the ftp client
# Arguments : host - host to connect, logFile - logFile path, port (optiona) - port number
# ------------------------------------------------------------------------------------------
if __name__ == "__main__":

    argumentLength = len(sys.argv)
    port = 21
    logFile = "client.log"

    # Parse Arguments
    if (argumentLength == 2):
        host = sys.argv[1]

    elif (argumentLength == 3):
        host, port = sys.argv[1], int(sys.argv[2])

    elif (argumentLength == 4):
        host, port, logFile = sys.argv[1], int(sys.argv[2]), sys.argv[3]

    else:
        print("\nUsage:\nftp_client.py hostname [port] [logfile]\n")
        exit(0)

    try:
        ftpSocket = FTPSocket(host, port, logFile)
    except:
        print("\nConnection Failed.\n")
        exit(0)
        
    try:
        ftp = FTP(host, ftpSocket)
        ftp.startProtocol()
    except:
        exit(0)
