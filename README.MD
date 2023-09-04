hack3270
========

```
usage: hack.py [options] IP PORT

Hack3270 - The TN3270 Penetration Testing Toolkit

positional arguments:
  IP                    TN3270 server IP address
  PORT                  TN3270 server port

options:
  -h, --help            show this help message and exit
  -n NAME, --name NAME  Project name (default: pentest)
  -p PROXY_PORT, --proxy_port PROXY_PORT
                        Local TN3270 proxy port (default: 3271)
  --proxy_ip PROXY_IP   Local TN3270 proxy IP (default: 127.0.0.1)
  -t, --tls             Enable TLS encryption for server connection (default: False)
  -o, --offline         Offline log analysis mode (default: False)
  -d, --debug           Print debugging statements (default: 30)

Example:
    hack.py -n prod_lpar3 10.10.10.10 992 -l 31337 --proxy_ip 0.0.0.0 --debug
    hack.py -o
```

Notes on command line options:

The `-n` (or `--name`) option determines the name of the SQLite3 log db file 
that is created.  By default this is 'pentest' and will create pentest.db.  The 
idea is that each mainframe application penetration test would have a different 
project name and all of the logs for that test would be written to the same 
database file.  If you stop the toolkit and then restart it will the same 
project name it will append to the exiting log .db file.  Setting for the server
IP, server port and local proxy port are saved as a configuration in this 
project .db file and will be setup when opening the project.  Eventhough the 
project DB has been setup, you need to provide these on the command line.

The `IP` and `PORT` options are to setup your connection to the mainframe. This
IP and port will be what you normally use in your tn3270 emulator to connect to
the mainframe. 

The `-p` (or `--proxy_port`) option sets the listening local port.  Connections
to this port are NOT encrypted.  This allows software such as Wireshark to be
used if the tester needs to create network packet captures; however if
connections to the mainframe are encrypted it is recommended to only connect to
the localhost host address (127.0.0.1) instead of connecting to this port
remotely, which would result in unencrypted tn3270 application data traversing
the network.

The `--proxy_ip` option sets the local ip address to listen on. Connections to 
this port are NOT encrypted. The default is 127.0.0.1.

The `-t` (or `--tls`) option enables TLS for the mainframe connection.  For the 
local connection, TLS is not implemented and is not required.

The `-o` (or `--offline`) option selects Offline log analysis mode.  This mode 
will not create a connection to the mainframe or append to the log file.  You 
still use a tn3270 terminal emulator to connect to the local port.  Once 
connected, selecting lines in the log of communication received from the server 
will be present to the connected terminal emulator.  This should render the 
display as seen during the time of testing.  Ideally your screen size should be 
the same as used when the log file was created.  This screen size can be seen in
the log during the initial tn3270 handshake.

The `-d` (or `--debug`) option enabled debug logging to the console. This
creates a lot of messages and should only be used when troubleshooting a problem
or when submitting an issue on github. 

Recommendations
---------------

Some initial recommendations under Linux to get going:  

* Currently this tool is only verified to work Python 3.11.1 on Linux
* Use x3270 or c3270 (or wx3270 under Windows) as your tn3270 terminal!
* Select Options->Screen Size->Model 5
* Select Options->Font and select whichever font that looks good for your screen size
* Click on the Keyboard icon on the top right of x3270 to display tn3270 keyboard for special keys
* Select File->Save Changed Options then click SAVE to store these settings

It is important to keep your screen size constant to ensure that when reviewing 
logs that the tn3270 screen will render properly.

Notes on how to use with DVCA (https://github.com/mainframed/DVCA):

* To exercise tool functionality, first execute the docker container: `sudo docker run -p 3270:3270 --expose=3270 mainframed767/dvca`
* For this example, we will use -n dvca to create a project log SQLite3 file named dvca.db: `./hack3270.py 127.0.0.1 3270 -n dvca`
* A window should appear saying that the tool is waiting for a connetion on port 3271
* Use x3270 and connect to 127.0.0.1 port 3271
* The window should populate with the following text: "Connection received". and "Click to Continue"
* Click the button and the full hack3270 GUI should launch
* The x3270 terminal will update with a logon screen
* Logon with DVCA password DVCA: `dvca/dvca`
* If the DVCA user is already logged in, type `LOGON DVCA RECONNECT` then the password to reconnect to the previous logon
* Click CLEAR on the x3270 keyboard then type MCGM to lauch DVCA application, then click PF5 on x3270 keyboard
* To exit DVCA hit the F3 button (on the virtual or real keyboard) then type KSSF, hit enter, then type `LOGOFF`

DVCA Demos
----------

* The first exploit demo is exercised in the 'Hack Field Attributes' tab.  Turn the Hack Fields button on and additional (previously hidden) options will apear
* Click on the Logs tab and scroll to the bottom of the log
* The last two log entries should be data received from the server and the bottom one should say TOGGLED ON and show the set options
* By clicking on this line, you will refresh that data to the tn3270 client, which will render the display
* If you click the line above it (or any other Server line) that data will be resent the to tn3270 client, allowing visual review of data previously received and logged
* By tracking these log entries, the log file may be audited to see exactly what actions the tester performed and allow the auditor to view exactly what the application looked like at the time of the test
* Because the data sizes are shown, this log system makes it VERY easy to identify when injected data causes a unique response
* For the next test, select the "Inject Key Presses" tab.
* It will auto-disable any PF key that appears in the text of the screen.  Click the Send Keys button to send all of the various function keys
* This will reveal a hidden display.  Click "Send Keys" button again and another hidden option will briefly appear
* Select the Logs tab and review the last entries.  You will see one entry with a different response size.  Click that line to display the hidden message.  Look at the log line before that for Client data to see which key was sent
* By reviewing futher back in the logs the specific PF key can be discovered that caused the first secret message
* By using up and down arrow, it is possible to scroll through the log entries and also see the x3270 screen being updated in real time.  This makes it easy to identify which injected input caused which server response
* Return to the main menu in DVCA and select option 2 (Shipping Address)
* To brute force the supervisor code, select the "Inject into Fields" tab, then click on the FILE button and select "dvca-demo-numeric-4.txt" file.
* Next, click SETUP button and it will tell you that your Mask character is "*" and that it is waiting for you to input data using that character.  This is used to identify the field that you wish to inject into.  Populate the 4 character of the supervisor code with "****" then hit enter
* Click on INJECT button to brute force the supervisor password
* Lastly, we may not have known the initial transaction of MCGM to launch this application, so we can use the "Inject into Fields" tab to solve that problem as well.
* Exit DVCA and hit the CLEAR button in x3270 keyboard
* Click the FILE button and select the "dvca-demo-transactions.txt" file, then click SETUP and type four of your mask character and hit enter.  If your mask is still "*" just type **** and then hit enter
* Before clicking inject, change the Keys: option at the right to ENTER+CLEAR.  This will clear the screen to exit out of the transaction before trying the next one.  For some applications, you actually have to exit by hitting PF3.  In that instance, select the Keys option of ENTER+PF3+CLEAR
* Click the INJECT button and several transactions will be attempted.  MCGM will briefly appear on the screen, if you have selected ENTER+CLEAR for Keys.  If you didn't change that and you still have just ENTER, it will become stuck after hitting the MCGM transaction, which is suboptimal, if you want to test a large list of possible transactions
* Using the Log tab it is possible to review the injected transaction attempts.  Just look for Server traffic with unusual lengths, click on those line and view what the server sent
