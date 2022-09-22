---

title: Hidden In Plain
date: 2022-09-23 12:00:00 +0200
tags: [Network Security, DFIR]     # TAG names should always be lowercase
author: abdelrahman671
categories: [CyberTalents Write-up]
comments: false
img_path: /assets/img/hip_imgs

---

![challenge image](st.png)


## Step 1:  

After downloading the zip file and extracting it. we will find three pcap files and analysing them by using `wireshark` tool.

First thing, let's check what procotols do they have via `Statistics > Protocol Hierarchy`

![protocol hierarchy](w1.png)

## Step 2:

Now, we can proceed with our analysis. Looking at the packets and we only observe the interesting thing is about the ICMP data.

![icmp packets](w2.png)

## Step 3:

It's the time to extract the icmp data from the packets using `tshark` or `pyshark` tools.

I have written a small script using `pyshark` to extract the icmp data.
```python
import pyshark
import sys

# stores pcap filename
filename = sys.argv[1]

# open pcap file
file = pyshark.FileCapture(filename)

# loop over each packet
for pkt in file:

    # fetch icmp data from packet as "57:00:..."
    cap = pkt.icmp.data_data

    # insert the fetched data into a list
    data_list = cap.split(":")

    #  storing the offset bytes in one string after converting it from hex to char

    offset = ""

    for i in data_list:
        offset += chr(int(i, 0x10))

    print(offset)   
```

After running the script, we will see the icmp data combined with strange symbols.

![icmp data](w3.png)

## Step 4:

There was nothing clear after extracting the icmp data. I stopped at this point then contacted the technical team for providing any hints for the challenge.

`Hint: yEnc Encrypted and the flag format is a hash`

I have searched for how it works and how to use it in python. Actually, I have found a yEnc module for python and it supports the encoding/decoding directly to files or memory buffers.

At this time, I have modified the script in order to implement the decode operation on the extracted icmp data to see what will be the results.

```python
import pyshark
import sys
import yenc

# stores pcap filename
filename = sys.argv[1]

# open pcap file
file = pyshark.FileCapture(filename)

# loop over each packet
for pkt in file:

    # fetch icmp data from packet as "57:00:..."
    cap = pkt.icmp.data_data

    # insert the fetched data into a list
    data_list = cap.split(":")

    #  storing the offset bytes in one string after converting it from hex to char

    offset = ""

    for i in data_list:
        offset += chr(int(i, 0x10))

    # storing the encoding yenc icmp data into an input file

    inputFile = sys.argv[2]

    with open(inputFile, "a", encoding="latin-1") as f:
        f.write(offset)

    # decoding yenc icmp data to an output file

    outputFile = sys.argv[3]
   
    yenc.decode(inputFile, outputFile)
```

## Step 5:

Executing the script by giving it the following arguments:
* pcap file name
* input file to store the yenc encoded data
* output file to decode the yenc encoded data 

![execution of a python script](w4.png)

When running the script on the first pcap file `f101.pcap`, I found something that might be interested from the decode operation.

![decoded icmp data](w5.png)

## Step 6

I have copied and inserted this data on [CyberChef](https://gchq.github.io/CyberChef/) then found that this is a base64 encoding, after decoding it we observe the output result.

![cyberchef output result](w6.png)

We still need to perform another operation in order to get the flag. So let's get the md5 hash of the "flag" word.

![md5 hash for 'flag' word](w7.png)

finally! the flag is : `flag{327a6c4304ad5938eaf0efb6cc3e53dc}`
   
