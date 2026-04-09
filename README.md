# checkip
This tool uses the Virus Total and AbuseIPDB APIs to quickly check an IP address and display the results in a clean format. Just add your API keys to the .env file.

---------
## Usage 

- To check a single IP:
  > *python checkip.py [ip_address]*

- To check a list of IPs from a text file:
  > *python checkip.py [text_file_name]*

- To save the output to a text file
  > *python checkip.py [ip_address **or** text_file_name] -o [filename]*
  > <br><br>**OR**<br><br>
  > *python checkip.py [ip_address **or** text_file_name] --output [filename]*
  
---------
### Example output with 8.8.8.8 (Google DNS)

<img width="565" height="532" alt="image" src="https://github.com/user-attachments/assets/9f5833e7-1353-4de9-ba0e-ca09a41a75d3" />

---------
### Example output with 204.76.203.30 (known malicious IP)

<img width="557" height="542" alt="image" src="https://github.com/user-attachments/assets/efe50de0-4ed9-4e06-9319-e4c0c7b27b21" />

---------
### Example output with a list and saving to text file

<img width="725" height="960" alt="screenshotThree" src="https://github.com/user-attachments/assets/52bc04b2-cd33-492e-b808-d130692bc4a6" />
<br>
I only have two IPs in the list just so the entire output would be visible.
