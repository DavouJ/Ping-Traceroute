#!/usr/bin/env python3
# -*- coding: UTF-8 -*-


import argparse
import socket
import os
import sys
import struct
import time
import select
#from socket import *

ICMP_ECHO_REQUEST = 8





def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.203.')
        parser.set_defaults(func=ICMPPing, hostname='google.co.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=4)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=4, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)

        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        args = parser.parse_args()
        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: str) -> str:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): ttl=%d time=%.2f ms" % (packetLength, destinationHostname, destinationAddress, ttl, time))
        else:
            print("%d bytes from %s: ttl=%d time=%.2f ms" % (packetLength, destinationAddress, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))


class ICMPPing(NetworkApplication):

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout):
                                                                                        #print('called receiveOnePing function!')

        remainingTime = timeout
        # 1. Wait for the socket to receive a reply
        # 2. Once received, record time of receipt, otherwise, handle a timeout
        # 3. Compare the time of receipt to time of sending, producing the total network delay
        while True:
        
                startSel = time.time()
                #print("startr sel is ", startSel)
                ready = select.select([icmpSocket],[],[], remainingTime)
                #print("timer is ", ready)
                timeInSel = (time.time() - startSel)
                #print("time in sel is ", timeInSel)

                if ready[0] == []:
                        return "timed out"
                        
                
                
                recvPacket, address = icmpSocket.recvfrom(1024)
                
                newTime = time.time()
        # 4. Unpack the packet header for useful information, including the ID
                icmph = recvPacket[20:28]
                type, code, checksum,pID, sq = struct.unpack("bbHHh", icmph)
   
        
        # 5. Check that the ID matches between the request and reply
        # 6. Return total network delay
                if pID == ID:
                        
                        
                        #bytesinDbl = struct.calcsize("d")
                        #timeSent = struct.unpack("d", recPacket[28:28 + bytesinDbl])[0]
                        #print("recieve time is ", newTime)
                        #print("delay is " ,newTime - sendTime)
                        
                        return newTime - sendTime
                
                remainingTime = newTime - timeInSel

                if remainingTime <= 0:
                        return "timed out"
                        
        
        pass

    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        global sendTime                                                      #print('called sendOnePing function!')
        # 1. Build ICMP header
        myChecksum = 0

        header = struct.pack("bbHIh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)

        data = struct.pack('d', time.time())

        # 2. Checksum ICMP packet using given function
        myChecksum = self.checksum(header + data)
        
        # 3. Insert checksum into packet
        header = struct.pack("bbHIh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
        packet = header + data
        
        # 4. Send packet using socket
        icmpSocket.sendto(packet, (destinationAddress, 1))
        
        # 5. Record time of sending
        sendTime = time.time()
        #print('sednd time is ', sendTime)
        return packet
        

    def doOnePing(self, destinationAddress, timeout):
        # 1. Create ICMP socket
        icmp = socket.getprotobyname('icmp')
        
        try:
                icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        except socket.error as e:
                if e.errno in ERROR_DESCR:
                    # Operation not permitted
                    raise socket.error(''.join((e.args[1], ERROR_DESCR[e.errno])))
            
        
        # 2. Call sendOnePing function
        ID = os.getpid()
        
        
        self.sendOnePing(icmpSocket, destinationAddress, ID)
        # 3. Call receiveOnePing function
        
        delay = self.receiveOnePing(icmpSocket, destinationAddress, ID, timeout)
        # 4. Close ICMP socket
        icmpSocket.close()
        # 5. Return total network delay
        return delay

    def __init__(self, args):
        
        print('Ping to: %s...' % (args.hostname))
        #args.hostname
        # 1. Look up hostname, resolving it to an IP address
        self.destinationAddress = socket.gethostbyname(args.hostname)

        
        l = 1
        while l != 10:
        # 2. Call doOnePing function, approximately every second
                delay = self.doOnePing(self.destinationAddress, 1)
        # 3. Print out the returned delay (and other relevant details) using the printOneResult method
        # 4. Continue this process until stopped
                if delay != "timed out":
                        self.printOneResult(self.destinationAddress, 50, delay*1000, sendTime, args.hostname)
                        l += 1
                else:
                        print(delay)
                        return
                        
                time.sleep(1)
        
        
                
class Traceroute(NetworkApplication):
        
    def __init__(self, args):
        print('Trace to: %s...' % (args.hostname))
        
        """

        # 1. Look up hostname, resolving it to an IP address
        self.destinationAddress = socket.gethostbyname(args.hostname)
        print('Trace to: %s...' % (self.destinationAddress))
        
        self.trace(self.destinationAddress, 2.0, 30)
        

    def trace(self, destinationAddress, timeout, hopLimit):
        timeLeft = timeout
        packetsLost=0
        minDelay = 0
        maxDelay = 0
        averageDelay = 0
        final = 0

        for ttl in range(1,hopLimit):
            #create socket
                icmp = socket.getprotobyname('icmp')
                
                icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
                
                icmpSocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
                icmpSocket.settimeout(timeout)

                try:
                    #builds packet
                    packet = self.makePacket()

                    #sends it and records time
                    icmpSocket.sendto(packet, (destinationAddress, 0))

                    sendTime = time.time()

                    
                    startSel = time.time()
                    ready = select.select([icmpSocket], [],[], timeLeft)
                    timeInSel = (time.time() - startSel)

                    
                    if ready[0] == []:
                        print ("*   *timed out*   *")

                    #receive packet and record time                    
                    recvPacket, address = icmpSocket.recvfrom(1024)

                    newTime = time.time()

                    if final == 1:
                        break

                    if address[0] == self.destinationAddress:
                        final = 1
                        
                                    
                    
                    timeLeft = timeLeft - timeInSel

                    #record rtt
                    rtt = newTime - sendTime

                    if timeLeft <= 0:
                        packetsLost +=1
                        print("*   *timed out*   *")

                except socket.timeout:    
                    continue

                else:
                    icmph = recvPacket[20:28]
                    requestType, code, checksum,pID, seq = struct.unpack("bbHHh", icmph)

                    if requestType == 11:
                        size = struct.calcsize("d")
                        tSent = struct.unpack("d", recvPacket[28:28 + size])[0]
                        self.printOneResult(address[0], size, rtt*1000, ttl, address)
                    elif requestType == 3:
                        size = struct.calcsize("d")
                        tSent = struct.unpack("d", recvPacket[28:28 + size])[0]
                        self.printOneResult(address[0], size, rtt*1000, ttl, address)
                    elif requestType == 0:
                        size = struct.calcsize("d")
                        tSent = struct.unpack("d", recvPacket[28:28 + size])[0]
                        self.printOneResult(address[0], size, rtt*1000, ttl, address)
                    else:
                        print("error")
                        break
                    if rtt < minDelay or minDelay == 0:
                        minDelay = rtt*1000
                    if rtt > maxDelay or maxDelay == 0:
                        maxDelay = rtt*1000

                     

                finally:
                    icmpSocket.close()
        averageDelay = (minDelay + maxDelay)/2
        self.printAdditionalDetails(packetsLost, minDelay, averageDelay, maxDelay)

    def makePacket(self):
        myChecksum = 0
        ID = os.getpid()

        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)

        data = struct.pack('d', time.time())

        myChecksum = self.checksum(header + data)

        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)

        packet = header + data

        return packet
    
    """

    
    


    


 
class WebServer(NetworkApplication):

    def handleRequest(tcpSocket):
        # 1. Receive request message from the client on connection socket
        # 2. Extract the path of the requested object from the message (second part of the HTTP header)
        """
        read = clientSoc.recv(5000).decode()
        readLine = read.split('\r\n')

        get, post, head = readLine.split('')

        print('yo')
        # 3. Read the corresponding file from disk
        # 4. Store in temporary buffer
        # 5. Send the correct HTTP response error
        # 6. Send the content of the file to the socket
        # 7. Close the connection socket
        pass

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
        # 1. Create server socket
        serverSoc = socket(AF_INET, SOCK_STREAM)

        # 2. Bind the server socket to server address and server port
        try:
            serverSoc.bind(('localhost', args.port))
            serverSoc.listen(0)

        # 3. Continuously listen for connections to server socket
            while(1):
                (clientSoc, address) = serverSoc.accept()
        except KeyboardInterrupt:
            print("stopped")
        except Exception as exc:
            print(exc)
        # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
            handleRequest(clientSoc)
        # 5. Close server socket
        serverSoc.close()

"""

class Proxy(NetworkApplication):

    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))


if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)


