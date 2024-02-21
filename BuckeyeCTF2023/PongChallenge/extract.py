import json

with open("data.json", "r") as read_file:
    data = json.load(read_file)

s = ""
for x in data:
    # Only read data from ping replys
    if("icmp.no_resp" not in x["_source"]["layers"]["icmp"]):
        # Truncate first 144 characters of response data as this corresponds 
        # to the first 48 bytes + 48 ':' characters between that are part of 
        # the ICMP Ping data and not part of the image
        if "data" in x["_source"]["layers"]["icmp"]:
        #     print(x["_source"]["layers"]["icmp"]["data"]["data.data"])
            s += x["_source"]["layers"]["icmp"]["data"]["data.data"][144:]
        else:
            print(x["_source"]["layers"]["frame"]["frame.number"])

f = open("out.txt","a")
f.write(s)
f.close()