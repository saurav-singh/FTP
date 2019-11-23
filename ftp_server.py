import os
import sys
import ssl
import socket
import threading
from ftp_logger import Logger

BUFFER = 2048
lock = threading.Lock()
log = None
CONFIG = {}
CONFIG["port_mode"] = None
CONFIG["pasv_mode"] = None
CONFIG["tsl_mode"] = None
allowed_users = {}


# ------------------------------------------------------------------------------------------
# FTP Server class :
# Initializes and starts the server
# Runs a new thread for every new client
# ------------------------------------------------------------------------------------------
class FTPServer:
    # --------------------------------------------------------------------------------------
    # Attributes:
    # port - Port number to run the server
    # host - Server's host name
    # hostIP - Server's host IP
    # socket - Server socket which listens to incomming connections
    # --------------------------------------------------------------------------------------
    def __init__(self, port):
        self.port = port
        self.host = socket.gethostname()
        self.hostIP = socket.gethostbyname(self.host)
        self.socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    
    def createCtx(self):
        context = ssl.create_default_context()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile="certificate.cert",keyfile="key.key")
        return context

    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)      
        self.socket.bind(("", self.port))
        self.socket.listen(5)

        # Print and Log initial message
        print()
        Log("Server started.", "Internal", True)
        msg = "Listening at Host: " + self.host
        msg += " IP: " + self.hostIP + " Port: " + str(self.port)
        Log(msg, "Internal", True)

        # Run the server
        while True:
            try:
                (C, A) = self.socket.accept()
                # Activate Secured TLS mode if ON in config
                if CONFIG["tls_mode"]:
                    context = self.createCtx()
                    C = context.wrap_socket(C, server_side=True)
                msg = "Connection from "
                msg += str(A[0]) + ":" + str(A[1]) + " established."
                Log(msg, "Internal", True)
                clientThread = FTPClientHandler(C, A)
                clientThread.start()
            except:
                pass

# ------------------------------------------------------------------------------------------
# FTP Client Handler Class:
# Concurrently handles multiple FTP client commands
# ------------------------------------------------------------------------------------------
class FTPClientHandler(threading.Thread):
    # --------------------------------------------------------------------------------------
    # Attributes:
    # clientSocket - client's socke for communicating
    # clientAddress - client's host address and port number to which it is connected to
    # basePath - base path of the server
    # currPath - current path of the server
    # dataPort - data port number for socket data connection
    # dataSocket - data socket for socket data connection
    # connected - connection status of the client
    # authenticated - authentication status of the client
    # passive - passive mode status
    # username - username entered by the client
    # password - password entered by the  client
    # message - most recent message to the client
    # --------------------------------------------------------------------------------------
    def __init__(self, clientSocket, clientAddress):
        threading.Thread.__init__(self)
        self.clientSocket  = clientSocket
        self.clientAddress = clientAddress
        self.basePath      = os.getcwd()
        self.currPath      = os.getcwd()
        self.dataPort      = 20
        self.dataSocket    = None
        self.connected     = True
        self.authenticated = False
        self.passive       = False
        self.username      = ""
        self.password      = ""
        self.message       = ""

    # --------------------------------------------------------------------------------------
    # Function - Start the client thread when initialzed
    #          - Concurrently handles the FTP protocols with the client
    # --------------------------------------------------------------------------------------
    def run(self):
        # Server welcome notice
        self.message = self.createMessage(220)
        self.send(self.message)

        # Do Protocol
        while self.connected:
            try:
                # Read Command
                command = self.recv()
                # Process Command
                self.processCommand(command)
                # Send Back message
                self.send(self.message)
            except:
                self.connected = False
                pass

        # Log the disconnected message
        msg = "Client disconnected"
        action = str(self.clientAddress[0]) + ":" + str(self.clientAddress[1])
        Log(msg, action, True)

        # Terminate the thread
        self.stop()

    # --------------------------------------------------------------------------------------
    # Function - Terminate the current thread
    # --------------------------------------------------------------------------------------
    def stop(self):
        self._is_running = False

    # --------------------------------------------------------------------------------------
    # Function - Send message to the client
    # Parameters : message - Message to be sent
    # --------------------------------------------------------------------------------------
    def send(self, message):
        # Log the message to be sent
        action = str(self.clientAddress[0]) + ":" + str(self.clientAddress[1])
        msg = "Message sent: " + message
        Log(msg, action, True)

        # Send the message to the  client
        message = Encode(message + "\r\n")
        self.clientSocket.send(message)

    # --------------------------------------------------------------------------------------
    # Function - Receive commands from the client
    # Parameters : none
    # --------------------------------------------------------------------------------------
    def recv(self):
        # Retrieve and decode the message
        message = self.clientSocket.recv(BUFFER)
        message = Decode(message)

        # Log the received message to be sent
        action = str(self.clientAddress[0]) + ":" + str(self.clientAddress[1])
        msg = "Received command: " + message
        Log(msg, action, True)

        # Return command
        return (message)

    # --------------------------------------------------------------------------------------
    # Function - Check for validation and set message
    # Parameters : none
    # --------------------------------------------------------------------------------------
    def authenticate(self):
        try:
            if allowed_users[self.username] == self.password:
                return True
            return False
        except:
            return False
    # --------------------------------------------------------------------------------------
    # Function - Process the command received from the client and execute the procotol
    # Parameters : command - command to process
    # --------------------------------------------------------------------------------------

    def processCommand(self, command):
        # USER, PASS, CWD, CDUP, QUIT, PASV, EPSV, PORT, EPRT, RETR, STOR, PWD, LIST.
        command = command[:-2].split(" ")
        commandLen = len(command)

        commands = {
            "USER": self.USER,
            "PASS": self.PASS,
            "CWD" : self.CWD,
            "XPWD": self.PWD,
            "PWD" : self.PWD,
            "QUIT": self.QUIT,
            "CDUP": self.CDUP,
            "PASV": self.PASV,
            "EPSV": self.EPSV,
            "PORT": self.PORT,
            "EPRT": self.EPRT,
            "RETR": self.RETR,
            "STOR": self.STOR,
            "NLST": self.LIST,
            "LIST": self.LIST,
        }

        # Check for valid command and arguments
        if (commandLen == 0 or command[0] not in commands):
            self.message = self.createMessage(501)
            return

        # Fix commands with spaces for arguments
        if (commandLen > 1):
            command[1] = " ".join(command[1:])
            command = command[:2]

        # Execute Protocol for valid command
        func = commands.get(command[0])
        func(command)

    # --------------------------------------------------------------------------------------
    # Function - Returns message to be sent to the client for a reply code
    # Parameters : code - reply code
    # --------------------------------------------------------------------------------------
    def createMessage(self, code):
        message = {
            150: "150 File status okay. About to open data connection",
            151: "150 Here comes the directory listing.",
            200: "200 Command okay.",
            201: "200 Port command successful. Consider using PASV.",
            220: "220 Service ready for new user.",
            221: "221 Goodbye.",
            226: "226 Closing data connection. Requested file action successful.",
            227: "227 Entering Passive Mode ",
            229: "229 Entering Extended Passive Mode ",
            230: "230 Login successful.",
            231: "230 Already logged in.",
            250: "250 Directory successfully changed.",
            257: "257 " + self.currPath,
            331: "331 User name okay, need password.",
            421: "421 Connection timed out.",
            422: "421 Connection aborted - Server error.",
            425: "425 Can't open data connection.",
            451: "451 Requested action aborted. Data connection not open.",
            500: "500 Unknown command.",
            501: "501 Syntax error in parameters or arguments.",
            502: "502 Command not supported.",
            503: "503 Bad sequence of commands.",
            530: "530 Not logged in.",
            531: "530 Login incorrect.",
            550: "550 Request action not taken. File unavailable."
        }
        return message.get(code)

    # --------------------------------------------------------------------------------------
    # Function - Checks if the arguments are valid for certain commands
    # Parameters : command - command to check, N - number of arugments required
    # --------------------------------------------------------------------------------------
    def validArgument(self, command, N=2):
        if (len(command) == N):
            return True
        self.message = self.createMessage(501)
        return False

    # --------------------------------------------------------------------------------------
    # Parses port two ways
    # --------------------------------------------------------------------------------------
    def parsePort(self, port):
        if (isinstance(port, tuple)):
            p1, p2 = int(port[0]), int(port[1])
            return int((p1 * 256) + p2)

        if (isinstance(port, int)):
            p2 = int(port % 256)
            p1 = int((port - p2) / 256)
            return str(p1), str(p2)

    # --------------------------------------------------------------------------------------
    # Data Socket Functions ----------------------------------------------------------------
    # --------------------------------------------------------------------------------------

    # --------------------------------------------------------------------------------------
    # Send Data via data socket
    # --------------------------------------------------------------------------------------
    def dataSend(self, data):
        try:
            dataSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            if self.passive:
                (dataSocket, clientAddress) = self.dataSocket.accept()
                self.dataSocket.close()
                self.dataSocket = None
                if clientAddress[0] != self.clientAddress[0]:
                    Log("Client IP mismatch. Possible intruder.","Internal",True)
                    self.message = self.createMessage(422)
                    return
            else:
                dataSocket.connect((self.clientAddress[0], self.dataPort))

            for _bytes in data:
                if (isinstance(_bytes, str)):
                    _bytes = Encode(_bytes + "\r\n")
                dataSocket.send(_bytes)

            dataSocket.close()

            self.message = self.createMessage(226)
        except socket.error as Err:
            Log(Err, "Internal", True)
            self.message = self.createMessage(425)

    # --------------------------------------------------------------------------------------
    # Receive Data via data socket
    # --------------------------------------------------------------------------------------
    def dataRecv(self):
        try:
            dataSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            if self.passive:
                (dataSocket, clientAddress) = self.dataSocket.accept()
                self.dataSocket.close()
                self.dataSocket = None
                if clientAddress[0] != self.clientAddress[0]:
                    Log("Client IP mismatch. Possible intruder.","Internal",True)
                    self.message = self.createMessage(422)
                    return
            else:
                dataSocket.connect((self.clientAddress[0], self.dataPort))

            data = bytearray()
            while True:
                _byte = dataSocket.recv(BUFFER)
                if (not _byte):
                    break
                data.extend(_byte)

            self.message = self.createMessage(226)

            return data
        except socket.error as Err:
            Log(Err, "Internal", True)
            self.message = self.createMessage(425)
            return

    # --------------------------------------------------------------------------------------
    # Receive Data via data socket
    # --------------------------------------------------------------------------------------
    def dataListen(self):
        with lock:
            host = socket.gethostname()
            self.dataSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.dataSocket.bind((host, 0))
            self.dataSocket.listen(5)
        self.dataPort = self.dataSocket.getsockname()[1]

    # --------------------------------------------------------------------------------------
    # FTP Protocol Functions ---------------------------------------------------------------
    # --------------------------------------------------------------------------------------

    # --------------------------------------------------------------------------------------
    # USER - Retrieve Username
    # --------------------------------------------------------------------------------------
    def USER(self, command):
        if self.validArgument(command):
            self.username = command[1]
            self.message = self.createMessage(331)

    # --------------------------------------------------------------------------------------
    # PASS - Retrieve Password and authenticate
    # --------------------------------------------------------------------------------------
    def PASS(self, command):
        if self.validArgument(command):
            self.password = command[1]

            if (self.authenticated):
                self.message = self.createMessage(231)
            else:
                self.authenticated = self.authenticate()
                if self.authenticated:
                    self.message = self.createMessage(230)
                else:
                    self.message = self.createMessage(531)

    # --------------------------------------------------------------------------------------
    # QUIT - Terminate the connection
    # --------------------------------------------------------------------------------------
    def QUIT(self, command):
        if self.validArgument(command, 1):
            self.connected = False
            self.message = self.createMessage(221)

    # --------------------------------------------------------------------------------------
    # PWD - Print working directory
    # --------------------------------------------------------------------------------------
    def PWD(self, command):
        if not self.authenticated:
            self.message = self.createMessage(530)
            return

        if self.validArgument(command, 1):
            self.message = self.createMessage(257)

    # --------------------------------------------------------------------------------------
    # CWD - Change working directory
    # --------------------------------------------------------------------------------------
    def CWD(self, command):
        if not self.authenticated:
            self.message = self.createMessage(530)
            return

        if self.validArgument(command):
            try:
                os.chdir(self.currPath)
                os.chdir(command[1])
                self.currPath = os.getcwd()
                os.chdir(self.basePath)
                self.message = self.createMessage(250)
            except:
                self.message = self.createMessage(550)

    # --------------------------------------------------------------------------------------
    # DCUP - Change to parent directory
    # --------------------------------------------------------------------------------------
    def CDUP(self, command):
        if not self.authenticated:
            self.message = self.createMessage(530)
            return

        if self.validArgument(command, 1):
            try:
                os.chdir(self.currPath)
                os.chdir("..")
                self.currPath = os.getcwd()
                os.chdir(self.basePath)
                self.message = self.createMessage(250)
            except:
                self.message = self.createMessage(550)

    # --------------------------------------------------------------------------------------
    # LIST - List directory
    # --------------------------------------------------------------------------------------
    def LIST(self, command):
        if not self.authenticated:
            self.message = self.createMessage(530)
            return
        
        # Error checking for data socket PASV
        if self.passive and self.dataSocket == None:
            self.message = self.createMessage(451)
            return

        # Error checking for data socket PORT
        if not self.passive and CONFIG["port_mode"] == False:
            self.message = self.createMessage(451)
            return  
    
        # Current directory listing
        os.chdir(self.currPath)
        if len(command) > 1:
            os.chdir(command[1])
        data = os.listdir(".")

        # Remove server and user database and config
        try:
            data.remove("serverFTP.py")
            data.remove("users.db")
            data.remove("server.conf")
            data.remove("certificate.cert")
            data.remove("key.key")
        except:
            pass

        # Format the directory listing format
        for i in range(len(data)):
            _file = data[i]
            # Determine size if valid
            if not os.path.isdir(_file):
                _size = os.stat(_file).st_size
            else:
                _size = ""
            data[i] = "{:20}{:15}{}".format(_file, "-" * 13, _size)

        data.insert(0, "{:20}{:15}{}".format("-" * 9, "", "-" * 9))
        data.insert(0, "{:20}{:15}{}".format("File Name", "", "File Size"))
        data.insert(0, "\n")
        data.insert(len(data), "\n")

        # Change back to base path.
        os.chdir(self.basePath)

        # Send back data
        self.message = self.createMessage(151)
        self.send(self.message)
        self.dataSend(data)

    # --------------------------------------------------------------------------------------
    # RETR - Send files to the client
    # --------------------------------------------------------------------------------------
    def RETR(self, command):
        if not self.authenticated:
            self.message = self.createMessage(530)
            return

        if self.validArgument(command):
            try:
                os.chdir(self.currPath)
                F = open(command[1], "rb")
                data = F.read()
                F.close()
                os.chdir(self.basePath)
            except:
                self.message = self.createMessage(550)
                return

            self.message = self.createMessage(150)
            self.send(self.message)
            self.dataSend([data])

    # --------------------------------------------------------------------------------------
    # STOR - Receive files from the client
    # --------------------------------------------------------------------------------------
    def STOR(self, command):
        if not self.authenticated:
            self.message = self.createMessage(530)
            return

        if self.validArgument(command):
            try:
                self.message = self.createMessage(150)
                self.send(self.message)
                data = self.dataRecv()
                os.chdir(self.currPath)
                F = open(command[1], "wb+")
                F.write(data)
                F.close()
                os.chdir(self.basePath)
            except:
                self.message = self.createMessage(550)

    # --------------------------------------------------------------------------------------
    # PORT - Active data transfer mode
    # --------------------------------------------------------------------------------------
    def PORT(self, command):
        if not self.authenticated:
            self.message = self.createMessage(530)
            return
        
        if not CONFIG["port_mode"]:
            self.message = self.createMessage(502)
            return    

        if self.validArgument(command):
            command = command[1].split(",")[-2:]
            port = self.parsePort((command[0], command[1]))

            if not (0 <= port <= 65535):
                self.message = self.createMessage(501)
                return

            self.dataPort = port
            self.passive = False
            self.message = self.createMessage(201)

    # --------------------------------------------------------------------------------------
    # EPRT - Active data transfer mode (Ipv4 and Ipv6)
    # --------------------------------------------------------------------------------------
    def EPRT(self, command):
        if not self.authenticated:
            self.message = self.createMessage(530)
            return
        
        if not CONFIG["port_mode"]:
            self.message = self.createMessage(502)
            return    

        if self.validArgument(command):
            port = int(command[1][-6:-1])

            if not (0 <= port <= 65535):
                self.message = self.createMessage(501)
                return

            self.dataPort = int(port)
            self.passive = False
            self.message = self.createMessage(201)
            print(self.message)

    # --------------------------------------------------------------------------------------
    # PASV - Active passive mode
    # --------------------------------------------------------------------------------------
    def PASV(self, command):
        if not self.authenticated:
            self.message = self.createMessage(530)
            return
        
        if not CONFIG["pasv_mode"]:
            self.message = self.createMessage(502)
            return    

        if self.validArgument(command, 1):
            host = socket.gethostname()
            hostIP = socket.gethostbyname(host).replace(".", ",")

            self.dataListen()
            (p1, p2) = self.parsePort(self.dataPort)

            self.passive = True
            self.message = self.createMessage(227)
            self.message += "(" + hostIP + "," + p1 + "," + p2 + ")."

    # --------------------------------------------------------------------------------------
    # EPSV - Active passive mode (Ipv4 and Ipv6)
    # --------------------------------------------------------------------------------------
    def EPSV(self, command):
        if not self.authenticated:
            self.message = self.createMessage(530)
            return
        
        if not CONFIG["pasv_mode"]:
            self.message = self.createMessage(502)
            return    

        if self.validArgument(command, 1):
            self.dataListen()
            self.passive = True
            self.message = self.createMessage(229)
            self.message += "(|||" + str(self.dataPort)+")"

# --------------------------------------------------------------------------------------
# Helper Functions ---------------------------------------------------------------------
# --------------------------------------------------------------------------------------

# --------------------------------------------------------------------------------------
# Encode messages
# --------------------------------------------------------------------------------------
def Encode(msg):
    return msg.encode("utf-8")

# --------------------------------------------------------------------------------------
# Decode message
# --------------------------------------------------------------------------------------
def Decode(msg):
    return msg.decode("utf-8")

# --------------------------------------------------------------------------------------
# Function - Checks if a certain port is open
# Parameters : port - port to check
# --------------------------------------------------------------------------------------
def checkOpenPort(port):
    testSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        testSocket.bind((socket.gethostname(), port))
        testSocket.close()
        return True
    except:
        return False


# --------------------------------------------------------------------------------------
# Log / Print messages
# --------------------------------------------------------------------------------------
def Log(msg, action="", display=False):
    # Don't Log if there's error in logger
    if log == None:
        return

    # Format action view
    action_view = "[{:20}]: ".format(action)

    # Log the message
    log.logServer(msg, action)

    # Print to console if
    if display:
        print(action_view, msg)


# ------------------------------------------------------------------------------------------
# Main Function : Receives 2 - 3 arguments and executes the ftp client
# Arguments : host - host to connect, logFile - logFile path, port (optiona) - port number
# ------------------------------------------------------------------------------------------
if __name__ == "__main__":

    # Server Files
    userDB = "users.db"
    configFile = "server.conf"
    logFile = "server.log"

    # check for invalid arguments
    arugmentLength = len(sys.argv)
        
    if arugmentLength == 2:
        port = int(sys.argv[1])
    
    elif arugmentLength == 3:
        port, logFile =  int(sys.argv[1]), sys.argv[2]
    
    else:
        print("\nUsage:\nserverFTP.py logfile port\n")
        exit(0)

    # Check for valid port
    if not checkOpenPort(port):
        print("\nError: Port already in use. Select a different port number.\n")
        exit(0)

    # Initialize Logger
    try:
        log = Logger(logFile)
    except:
        Log("Failed to initialize log file.", "Internal", True)
        exit(0)

    # Initialize Authorized Users
    try:
        f = open(userDB, "r")
        dataList = f.read()
        f.close()
    except IOError as Err:
        Log(Err, "Internal", True)
        exit(0)
    
    # Parse Authorized Users
    dataList = dataList.split("\n")
    for data in dataList:
        data = data.split(",")
        allowed_users[data[0]] = data[1]
    
    # Initialize Config File
    try:
        f = open(configFile, "r")
        config = f.read()
        f.close()
    except IOError as Err:
        Log(Err, "Internal", True)
        exit(0)
    
    # Parse Config File
    config = config.split("\n")
    for line in config:
        if len(line) > 0 and line[0] != "#":
            line = line.replace(" ","").split("=")
            CONFIG[line[0]] = True if line[1].lower() == "yes" else False

    # Check Config Values
    try:
        if not CONFIG["port_mode"] and not CONFIG["pasv_mode"]:
            # Log("Fatal Error", "Internal", True)
            raise "Fatal Error"
    except:
        Log("Fatal Error", "Internal", True)
        exit(0)
    
    # Initialize Server
    try:
        server = FTPServer(port)
    except:
        Log("Failed to initialize Server.", "Internal", True)
        exit(0)

    # Start Server
    try:
        server.start()
    except:
        Log("Failed to start Server.", "Internal", True)
        exit(0)
