import datetime

'''
Logger for FTP client and server. 
'''

# ------------------------------------------------------------------------------------------
# Logger class :
# Handles all operations to log messages received by ftp client to a file
# ------------------------------------------------------------------------------------------


class Logger:
    # --------------------------------------------------------------------------------------
    # Attributes:
    # fileName - name / path of the log file, file - file pointer
    # --------------------------------------------------------------------------------------
    def __init__(self, fileName):
        self.fileName = fileName
        self.file = None

    # --------------------------------------------------------------------------------------
    # Open the log File
    # --------------------------------------------------------------------------------------
    def open(self):
        self.file = open(self.fileName, "a+")

    # --------------------------------------------------------------------------------------
    # Close the log File
    # --------------------------------------------------------------------------------------
    def close(self):
        self.file.close()

    # --------------------------------------------------------------------------------------
    # Get current date and time
    # --------------------------------------------------------------------------------------
    def currentDateTime(self):
        now = datetime.datetime.now()
        now = now.strftime("%m/%d/%Y %H:%M:%S")
        return str(now)

    # --------------------------------------------------------------------------------------
    # Parse and log the message to the log File
    # Parameters: msg - Message body, action - "Received" | "Sent" | "Connection" | "Data"
    # --------------------------------------------------------------------------------------
    def log(self, msg, action=""):
        if action == "Data":
            data = msg
        else:
            data = self.currentDateTime()
            data += " : "
            data += "[{:10}]: ".format(action)
            data += msg

        if (data[-1] != "\n"):
            data += "\n"

        try:
            self.open()
            self.file.write(data)
            self.close()
        except:
            pass

    # --------------------------------------------------------------------------------------
    # Parse and log the message to the log File
    # Parameters: msg - Message body, action - "Received" | "Sent" | "Connection" | "Data"
    # --------------------------------------------------------------------------------------
    def logServer(self, msg, action=""):
        if action == "Data":
            data = msg
        else:
            data = self.currentDateTime()
            data += " : "
            data += "[{:20}]: ".format(action)
            data += msg

        if (data[-1] != "\n"):
            data += "\n"

        try:
            self.open()
            self.file.write(data)
            self.close()
        except:
            pass
