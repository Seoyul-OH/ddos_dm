# Implementing DDoS Detection/Mitigation scheme on a Bmv2 p4 Switch  

This code is an ongoing work, which needs several updates to run correctly. 

Pre-Installation of dependencies are needed (PI, Behavioral Model (BMv2), P4C). 
They can be downloaded at https://github.com/jafingerhut/p4-guide


## Introduction

1.  Clone the repository to local 

    ```
    git clone https://github.com/Seoyul-OH/ddos_dm.git
    ```

2. ```
    cd ddos_dm
   ```

3. Define veths in your path 

```
sudo ./veth_setup.sh 
```

4. Compile the ddos_dm.p4 program 

```
p4c-bm2-ss --p4v 16 ddos_dm.p4 -o ddos_dm.json
```

5. Run the switch in background 
```
sudo simple_switch -i 0@veth0 -i 1@veth2 --log-console --thrift-port 9090 ddos_dm.json
```

Open a different terminal and then, 

6. Set hashes of the controller by running the `set_hashes` option (This is for the crc32_custom hashes)
```
sudo python3 cm-sketch-controller.py --option "set_hashes"
```

7. Send packets (Arguments are in sourceIP, destinationIP, interface)
```
sudo python3 send_1.py 10.0.2.2 10.0.1.1 veth1
```

(One packet will be sent)


8. Look at the logs from the first terminal, if a destination is contacted by "DDOS_threshold" sources, metadata digest will be changed to 1, and the victim destination IP will be stored. 
