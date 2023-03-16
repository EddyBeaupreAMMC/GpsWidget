#!/usr/bin/env python3

import json
import datetime

import PySimpleGUI as sg

import configparser

import re

import tftpy

import traceback

import syslog

import os

from shutil import which as FindExec

from io import TextIOWrapper

from time import sleep as Sleep
from threading import Thread
from typing import NamedTuple

from subprocess import run as SubProcessRun
from subprocess import PIPE as SubProcessPipe

import gpsd


class IPerfData(NamedTuple):
    start: float
    end: float
    seconds: float
    total_bytes: int
    bits_per_second: float
    jitter: float
    lost_packets: int
    packets: int
    lost_percent: float
    sender: bool


class IPerfResult(NamedTuple):
    latitde: float
    longitude: float
    speed: float
    altitude: float
    time: str
    client_sent: IPerfData
    client_receive: IPerfData
    client_summary: IPerfData
    server_sent: IPerfData
    server_receive: IPerfData
    server_sumary: IPerfData
    ping: float


class UpdateGPS:
    """Query GPS and update interface"""

    window: sg.Window = None
    event: str = None
    connect: bool = False
    enable: bool = False
    delay: int = 1
    thread: Thread = None

    def __init__(self, sgwindow: sg.Window, event: str, interval: int = 1) -> None:
        """Initialize the class

        Args:
            callback (Callable[[gpsd.GpsResponse], None]): callback for UI update
            interval (int, optional): interval between updates in seconds. Defaults to 1.
        """
        try:
            self.window = sgwindow
            self.event = event
            self.delay = interval
            self.thread = Thread(target=self.worker, daemon=True, name="UpdateGPS-Thread")
            self.thread.start()
        except Exception as e:
            for line in traceback.format_exc().splitlines():
                syslog.syslog(line)

    def enabled(self) -> None:
        """Enable GPS Updates"""
        self.enable = True

    def disabled(self) -> None:
        """Disable GPS Updated"""
        self.enable = False

    def worker(self):
        """Pool the GPS and call the callback with result"""
        while not self.connect:
            try:
                gpsd.connect()
                self.connect = True
            except Exception as e:
                for line in traceback.format_exc().splitlines():
                    syslog.syslog(line)
        while True:
            if self.enable == True:
                try:
                    self.window.write_event_value(self.event, gpsd.get_current())
                except Exception as e:
                    for line in traceback.format_exc().splitlines():
                        syslog.syslog(line)
            Sleep(self.delay)


class IPerf3:
    """Wrapper for IPerf3 (client mode)"""

    window: sg.Window = None
    event: str = None
    thread: Thread = None
    command: list = []
    enable: bool = False
    delay: int = 10

    def __init__(
            self, sgwindow: sg.Window, event: str, client: str, delay: int = 10, port: int = None, path: str = "/usr/local/bin/iperf3",
            affinity: str = None, bind: str = None, binddev: str = None, rcvtimeout: int = None, sndtimeout: int = None, udp: bool = None,
            connecttimeout: int = None, bitrate: int = None, pacingtimer: int = None, fqrate: int = None, time: int = None, tbytes: int = None,
            blockcount: int = None, length: int = None, cport: int = None, parallel: int = None, reverse: bool = None, bidir: bool = None,
            window: int = None, congestion: str = None, setmss: int = None, nodelay: bool = None, version4: bool = None, version6: bool = None,
            tos: int = None, dscp: int = None, flowlabel: int = None, zerocopy: bool = None, omit: int = None, extradata: str = None,
            getserveroutput: bool = None, udpcounters64bit: bool = None, repeatingpayload: bool = None, dontfragment: bool = None) -> None:
        """Initialize the class

        Args:
            window (sg.Window): window to generate an event.
            event (str): event to generate.
            client (str): server port to listen on/connect to.
            delay (int): interval between runs, default to 10 seconds.
            port (int, optional): server port to listen on/connect to. Defaults to iperf3's default value.
            path (str, optional): path to iperf3 binary. Defaults to "/usr/local/bin/iperf3".
            affinity (str, optional): set CPU affinity. Defaults to iperf3's default value.
            bind (str, optional): bind to the interface associated with the address <host>. Defaults to iperf3's default value.
            binddev (str, optional): bind to the network interface with SO_BINDTODEVICE. Defaults to iperf3's default value.
            rcvtimeout (int, optional): idle timeout for receiving data. Defaults to iperf3's default value.
            sndtimeout (int, optional): timeout for unacknowledged TCP data. Defaults to iperf3's default value.
            udp (bool, optional): use UDP rather than TCP. Defaults to iperf3's default value.
            connecttimeout (int, optional): timeout for control connection setup (ms). Defaults to iperf3's default value.
            bitrate (int, optional): target bitrate in bits/sec (0 for unlimited). Defaults to iperf3's default value.
            pacingtimer (int, optional): set the timing for pacing, in microseconds. Defaults to iperf3's default value.
            fqrate (int, optional): enable fair-queuing based socket pacing in bits/sec (Linux only). Defaults to iperf3's default value.
            time (int, optional): time in seconds to transmit for. Defaults to iperf3's default value.
            tbytes (int, optional): _number of bytes to transmit (instead of -t). Defaults to iperf3's default value.
            blockcount (int, optional): number of blocks (packets) to transmit (instead of -t or -n). Defaults to iperf3's default value.
            length (int, optional): length of buffer to read or write. Defaults to iperf3's default value.
            cport (int, optional): bind to a specific client port. Defaults to iperf3's default value.
            parallel (int, optional): number of parallel client streams to run. Defaults to iperf3's default value.
            reverse (bool, optional): run in reverse mode (server sends, client receives). Defaults to iperf3's default value.
            bidir (bool, optional): run in bidirectional mode. (Client and server send and receive data). Defaults to iperf3's default value.
            window (int, optional): set send/receive socket buffer sizes (indirectly sets TCP window size). Defaults to iperf3's default value.
            congestion (str, optional): set TCP congestion control algorithm (Linux and FreeBSD only). Defaults to iperf3's default value.
            setmss (int, optional): et TCP/SCTP maximum segment size (MTU - 40 bytes). Defaults to iperf3's default value.
            nodelay (bool, optional): set TCP/SCTP no delay, disabling Nagle's Algorithm. Defaults to iperf3's default value.
            version4 (bool, optional): only use IPv4. Defaults to iperf3's default value.
            version6 (bool, optional): only use IPv6. Defaults to iperf3's default value.
            tos (int, optional): set the IP type of service, 0-255. Defaults to iperf3's default value.
            dscp (int, optional): set the IP dscp value, 0-63. Defaults to iperf3's default value.
            flowlabel (int, optional): set the IPv6 flow label (only supported on Linux). Defaults to iperf3's default value.
            zerocopy (bool, optional): use a 'zero copy' method of sending data. Defaults to iperf3's default value.
            omit (int, optional): perform pre-test for N seconds and omit the pre-test statistics. Defaults to iperf3's default value.
            extradata (str, optional): data string to include in client and server JSON. Defaults to iperf3's default value.
            getserveroutput (bool, optional): get results from server. Defaults to iperf3's default value.
            udpcounters64bit (bool, optional): use 64-bit counters in UDP test packets. Defaults to iperf3's default value.
            repeatingpayload (bool, optional): use repeating pattern in payload, instead of randomized payload (like in iperf2). Defaults to iperf3's default value.
            dontfragment (bool, optional): set IPv4 Don't Fragment flag. Defaults to iperf3's default value.

        Yields:
            _type_: _description_
        """
        try:
            self.window = sgwindow
            self.event = event
            self.delay = delay
            self.cmdline(
                client=client, port=port, path=path, affinity=affinity, bind=bind, binddev=binddev, rcvtimeout=rcvtimeout,
                sndtimeout=sndtimeout, udp=udp, connecttimeout=connecttimeout, bitrate=bitrate, pacingtimer=pacingtimer,
                fqrate=fqrate, time=time, tbytes=tbytes, blockcount=blockcount, length=length, cport=cport, parallel=parallel,
                reverse=reverse, bidir=bidir, window=window, congestion=congestion, setmss=setmss, nodelay=nodelay,
                version4=version4, version6=version6, tos=tos, dscp=dscp, flowlabel=flowlabel, zerocopy=zerocopy, omit=omit,
                extradata=extradata, getserveroutput=getserveroutput, udpcounters64bit=udpcounters64bit,
                repeatingpayload=repeatingpayload, dontfragment=dontfragment)
            self.thread = Thread(target=self.worker, daemon=True, name="IPerf3-Thread")
            self.thread.start()
        except Exception as e:
            for line in traceback.format_exc().splitlines():
                syslog.syslog(line)

    def cmdline(
            self, client: str, port: int = None, path: str = "/usr/local/bin/iperf3", affinity: str = None, bind: str = None,
            binddev: str = None, rcvtimeout: int = None, sndtimeout: int = None, udp: bool = None, connecttimeout: int = None,
            bitrate: int = None, pacingtimer: int = None, fqrate: int = None, time: int = None, tbytes: int = None, blockcount: int = None,
            length: int = None, cport: int = None, parallel: int = None, reverse: bool = None, bidir: bool = None, window: int = None,
            congestion: str = None, setmss: int = None, nodelay: bool = None, version4: bool = None, version6: bool = None, tos: int = None,
            dscp: int = None, flowlabel: int = None, zerocopy: bool = None, omit: int = None, extradata: str = None,
            getserveroutput: bool = None, udpcounters64bit: bool = None, repeatingpayload: bool = None, dontfragment: bool = None) -> list:
        """build IPerf command line

        Args:
            client (str): server port to listen on/connect to.
            port (int, optional): server port to listen on/connect to. Defaults to iperf3's default value.
            path (str, optional): path to iperf3 binary. Defaults to "/usr/local/bin/iperf3".
            affinity (str, optional): set CPU affinity. Defaults to iperf3's default value.
            bind (str, optional): bind to the interface associated with the address <host>. Defaults to iperf3's default value.
            binddev (str, optional): bind to the network interface with SO_BINDTODEVICE. Defaults to iperf3's default value.
            rcvtimeout (int, optional): idle timeout for receiving data. Defaults to iperf3's default value.
            sndtimeout (int, optional): timeout for unacknowledged TCP data. Defaults to iperf3's default value.
            udp (bool, optional): use UDP rather than TCP. Defaults to iperf3's default value.
            connecttimeout (int, optional): timeout for control connection setup (ms). Defaults to iperf3's default value.
            bitrate (int, optional): target bitrate in bits/sec (0 for unlimited). Defaults to iperf3's default value.
            pacingtimer (int, optional): set the timing for pacing, in microseconds. Defaults to iperf3's default value.
            fqrate (int, optional): enable fair-queuing based socket pacing in bits/sec (Linux only). Defaults to iperf3's default value.
            time (int, optional): time in seconds to transmit for. Defaults to iperf3's default value.
            tbytes (int, optional): _number of bytes to transmit (instead of -t). Defaults to iperf3's default value.
            blockcount (int, optional): number of blocks (packets) to transmit (instead of -t or -n). Defaults to iperf3's default value.
            length (int, optional): length of buffer to read or write. Defaults to iperf3's default value.
            cport (int, optional): bind to a specific client port. Defaults to iperf3's default value.
            parallel (int, optional): number of parallel client streams to run. Defaults to iperf3's default value.
            reverse (bool, optional): run in reverse mode (server sends, client receives). Defaults to iperf3's default value.
            bidir (bool, optional): run in bidirectional mode. (Client and server send and receive data). Defaults to iperf3's default value.
            window (int, optional): set send/receive socket buffer sizes (indirectly sets TCP window size). Defaults to iperf3's default value.
            congestion (str, optional): set TCP congestion control algorithm (Linux and FreeBSD only). Defaults to iperf3's default value.
            setmss (int, optional): et TCP/SCTP maximum segment size (MTU - 40 bytes). Defaults to iperf3's default value.
            nodelay (bool, optional): set TCP/SCTP no delay, disabling Nagle's Algorithm. Defaults to iperf3's default value.
            version4 (bool, optional): only use IPv4. Defaults to iperf3's default value.
            version6 (bool, optional): only use IPv6. Defaults to iperf3's default value.
            tos (int, optional): set the IP type of service, 0-255. Defaults to iperf3's default value.
            dscp (int, optional): set the IP dscp value, 0-63. Defaults to iperf3's default value.
            flowlabel (int, optional): set the IPv6 flow label (only supported on Linux). Defaults to iperf3's default value.
            zerocopy (bool, optional): use a 'zero copy' method of sending data. Defaults to iperf3's default value.
            omit (int, optional): perform pre-test for N seconds and omit the pre-test statistics. Defaults to iperf3's default value.
            extradata (str, optional): data string to include in client and server JSON. Defaults to iperf3's default value.
            getserveroutput (bool, optional): get results from server. Defaults to iperf3's default value.
            udpcounters64bit (bool, optional): use 64-bit counters in UDP test packets. Defaults to iperf3's default value.
            repeatingpayload (bool, optional): use repeating pattern in payload, instead of randomized payload (like in iperf2). Defaults to iperf3's default value.
            dontfragment (bool, optional): set IPv4 Don't Fragment flag. Defaults to iperf3's default value.

        Returns:
            list: _description_
        """
        try:
            self.command.clear()
            self.command.append(path)
            self.command.append("--json")
            self.command.extend(["-c", client])
            if port != None:
                self.command.extend(["--port", str(port)])
            if affinity != None:
                self.command.extend(["--affinity", affinity])
            if bind != None:
                self.command.extend(["--bind", bind])
            if binddev != None:
                self.command.extend(["--bind-dev", binddev])
            if rcvtimeout != None:
                self.command.extend(["--rcv-timeout", str(rcvtimeout)])
            if sndtimeout != None:
                self.command.extend(["--snd-timeout", str(sndtimeout)])
            if udp == True:
                self.command.append("--udp")
            if connecttimeout != None:
                self.command.extend(["--connect-timeout", str(connecttimeout)])
            if bitrate != None:
                self.command.extend(["--bitrate", str(bitrate)])
            if pacingtimer != None:
                self.command.extend(["--pacing-timer", str(pacingtimer)])
            if fqrate != None:
                self.command.extend(["--fq-rate", str(fqrate)])
            if time != None:
                self.command.extend(["--time", str(time)])
            if tbytes != None:
                self.command.extend(["--bytes", str(tbytes)])
            if blockcount != None:
                self.command.extend(["--blockcount", str(blockcount)])
            if length != None:
                self.command.extend(["--length", str(length)])
            if cport != None:
                self.command.extend(["--cport", str(cport)])
            if parallel != None:
                self.command.extend(["--parallel", str(parallel)])
            if reverse == True:
                self.command.append("--reverse")
            if bidir == True:
                self.command.append("--bidir")
            if window != None:
                self.command.extend(["--window", str(window)])
            if congestion != None:
                self.command.extend(["--congestion", congestion])
            if setmss != None:
                self.command.extend(["--setmss", str(setmss)])
            if nodelay == True:
                self.command.append("--nodelay")
            if version4 == True:
                self.command.append("--version4")
            if version6 == True:
                self.command.append("--version6")
            if tos != None:
                self.command.extend(["--tos", str(tos)])
            if dscp != None:
                self.command.extend(["--dscp", str(dscp)])
            if flowlabel != None:
                self.command.extend(["--flowlabel", str(flowlabel)])
            if zerocopy == True:
                self.command.append("--zerocopy")
            if omit != None:
                self.command.extend(["--omit", str(omit)])
            if extradata != None:
                self.command.extend(["--extra-data", extradata])
            if getserveroutput == True:
                self.command.append("--get-server-output")
            if udpcounters64bit == True:
                self.command.append("--udp-counters-64bit")
            if repeatingpayload == True:
                self.command.append("--repeating-payload")
            if dontfragment == True:
                self.command.append("--dont-fragment")
        except Exception as e:
            for line in traceback.format_exc().splitlines():
                syslog.syslog(line)

    def enabled(self):
        self.enable = True

    def disabled(self):
        self.enable = False

    def worker(self):
        """Run IPerf and call the UI callback"""
        while True:
            try:
                if self.enable:
                    result = SubProcessRun(self.command, text=True, stdout=SubProcessPipe, stderr=SubProcessPipe, check=False)
                    if result.returncode == 0:
                        self.window.write_event_value(self.event, json.loads(result.stdout))
            except Exception as e:
                for line in traceback.format_exc().splitlines():
                    syslog.syslog(line)
            Sleep(self.delay)


class FPing:
    window: sg.Window = None
    event: str = None
    ip: str = None
    count: int = None
    interval: int = None
    ping_interval: int = None
    enable: bool = False
    thread: Thread = None
    path: str = None

    def __init__(self, sgwindow: sg.Window, event: str, ip: str, interval: int = 1, count: int = 5, ping_interval: int = 10, path: str = "/usr/bin/fping") -> None:
        """Do a fping and trigger an event in a window with the result

        Args:
            window (sg.Window): window to generate an event.
            event (str): event to generate.
            ip (str): ip address to ping.
            interval (int, optional): interval in seconds between runs. Minimum is 1 seconds . Defaults to 1.
            count (int, optional): number of ping to generate. Minimum is 5. Defaults to 5.
            ping_interval (int, optional): interval in ms between pings. Minimum is 10. Defaults to 10.
            path (str, optional): path to fping binary. Defaults to "/usr/bin/fping".
        """
        try:
            self.window = sgwindow
            self.event = event
            self.path = path
            self.ip = ip
            if count < 4:
                count = 5
            self.count = count
            if interval < 1:
                interval = 1
            self.interval = interval
            if ping_interval < 10:
                ping_interval = 10
            self.ping_interval = ping_interval
            self.thread = Thread(target=self.worker, daemon=True, name="FPing-Thread")
            self.thread.start()
        except Exception as e:
            for line in traceback.format_exc().splitlines():
                syslog.syslog(line)

    def worker(self):
        while True:
            try:
                if self.enable is True:
                    result = SubProcessRun([self.path, self.ip, "-c", str(self.count), "-q", "-p", str(self.ping_interval), "-R"], text=True, stdout=SubProcessPipe, stderr=SubProcessPipe, check=False)
                    if result.returncode == 0:
                        s = result.stderr.strip()
                        ip = s.split(":")[0].strip()
                        pkt = s.split(":")[1].split(",")[0].split("=")[1].strip().split("/")
                        ms = s.split(":")[1].split(",")[1].split("=")[1].strip().split("/")
                        self.window.write_event_value(self.event, {"ip": ip, "xmt": pkt[0], "rcv": pkt[1], "loss": pkt[0], "min": ms[0], "avg": ms[1], "max": ms[2]})
            except Exception as e:
                for line in traceback.format_exc().splitlines():
                    syslog.syslog(line)
            Sleep(self.interval)

    def enabled(self):
        self.enable = True

    def disabled(self):
        self.enable = False

class MainWindow:
    """_summary_"""

    layout: any = None
    fping: FPing = None
    window: sg.Window = None
    iperf: IPerf3 = None
    gps: UpdateGPS = None
    enabled_button_color: str = None
    disabled_button_color: str = None
    log_file: str = None
    history: list[IPerfResult] = []
    config:dict = {}

    def __init__(self, config:dict) -> None:
        try:
            self.config = config
            sg.theme(self.config['Default']['Theme'])
            self.layout = [
                [
                    sg.Frame("GPS", [
                        [
                            sg.Frame("Latitude", [[sg.Text("N/A", size=16, key="text_gps_latitude")]], border_width=1),
                            sg.Frame("Longitude", [[sg.Text("N/A", size=16, key="text_gps_longitude")]], border_width=1),
                            sg.Frame("Vitesse", [[sg.Text("N/A", size=16, key="text_gps_vitesse")]], border_width=1),
                            sg.Frame("Altitude", [[sg.Text("N/A", size=16, key="text_gps_altitude")]], border_width=1),
                            sg.Frame("Horloge", [[sg.Text("N/A", size=26, key="text_gps_horloge")]], border_width=1)
                        ]])
                ],
                [
                    sg.Frame("Contrôles", [
                        [
                            sg.Button("Start", size=(49, 10), key="btn_start"),
                            sg.Button("Stop", size=(49, 10), key="btn_stop")
                        ],
                        [
                            sg.Button("4Mbps", size=10, key="btn_speed_4"),
                            sg.Button("8Mbps", size=10, key="btn_speed_8"),
                            sg.Button("16Mbps", size=10, key="btn_speed_16"),
                            sg.Button("32Mbps", size=10, key="btn_speed_32"),
                            sg.Button("64Mbps", size=10, key="btn_speed_64"),
                            sg.Button("Max", size=10, key="btn_speed_max"),
                            sg.Button("Exit", size=11, key="btn_exit")
                        ]])
                ],
                [
                    sg.Frame("Performances", [
                        [
                            sg.Frame("Client", [
                                [
                                    sg.Frame("Envois", [[sg.Text("N/A", size=17, key="text_client_send")]], border_width=1),
                                    sg.Frame("Reception", [[sg.Text("N/A", size=17, key="text_client_recv",)]], border_width=1)
                                ]], border_width=0),
                            sg.Frame("Serveur", [
                                [
                                    sg.Frame("Envois", [[sg.Text("N/A", size=17, key="text_server_send",)]], border_width=1),
                                    sg.Frame("Reception", [[sg.Text("N/A", size=17, key="text_server_recv",)]], border_width=1)
                                ]], border_width=0),
                            sg.Frame(" ", [
                                [
                                    sg.Frame("Ping", [[sg.Text("N/A", size=18, key="text_ping")]], border_width=1)
                                ]], border_width=0)
                        ]])
                ]]
        except Exception as e:
            for line in traceback.format_exc().splitlines():
                syslog.syslog(line)

    def bytes_per_seconds(self, size: float, seconds: float, precision: int = 2) -> str:
        """Convert size and elapsed time to b/s, kb/s, ...

        Args:
            size (float): total size in bytes.
            seconds (float): total duration.
            precision (int, optional): number of digits for precision. Defaults to 2 digits.

        Returns:
            str: Human readable result
        """
        try:
            suffixes = ["b/s", "kb/s", "mb/s", "gb/s", "tb/s"]
            index = 0
            size = size / seconds
            while size > 1024 and index < 4:
                index += 1
                size = size / 1024.0
            return "%.*f%s" % (precision, size, suffixes[index])
        except Exception as e:
                for line in traceback.format_exc().splitlines():
                    syslog.syslog(line)

    def getiperfdata(self, data) -> IPerfData:
        try:
            return IPerfData(data["start"], data["end"], data["seconds"], data["bytes"], data["bits_per_second"], data["jitter_ms"], data["lost_packets"], data["packets"], data["lost_percent"], data["sender"])
        except Exception as e:
                for line in traceback.format_exc().splitlines():
                    syslog.syslog(line)

    def writeCSVIperf(self, csv: TextIOWrapper, data: IPerfData, prefix: str = None, header: bool = False):
        try:
            if header is True:
                if prefix is not None:
                    csv.write(',"' + prefix + '_start","' + prefix + '_end","' + prefix + '_seconds","' + prefix + '_total_bytes","' + prefix + '_bits_per_second","' + prefix + '_jitter","' + prefix + '_lost_packets","' + prefix + '_packets","' + prefix + '_lost_percent","' + prefix + '_sender"')
            else:
                csv.write("," + str(data.start) + "," + str(data.end) + "," + str(data.seconds) + "," + str(data.total_bytes) + "," + str(data.bits_per_second) + "," + str(data.jitter) + "," + str(data.lost_packets) + "," + str(data.packets) + "," + str(data.lost_percent) + "," + str(data.sender))
        except Exception as e:
            for line in traceback.format_exc().splitlines():
                syslog.syslog(line)

    def writeCSV(self, result: IPerfResult, header: bool = False):
        try:
            if self.log_file is not None:
                with open(os.environ.get('HOME') + "/Desktop/GpsWidget.log/" + self.log_file, 'a', newline='') as csv:
                    if header is True:
                        csv.write('"latitde"' + "," + '"longitude"' + "," + '"speed"' + "," + '"altitude"' + "," + '"time"')
                        self.writeCSVIperf(csv, None, "client_sent", True)
                        self.writeCSVIperf(csv, None, "client_receive", True)
                        self.writeCSVIperf(csv, None, "client_summary", True)
                        self.writeCSVIperf(csv, None, "server_sent", True)
                        self.writeCSVIperf(csv, None, "server_receive", True)
                        self.writeCSVIperf(csv, None, "server_sumary", True)
                        csv.write(',"ping"\n')
                    else:
                        csv.write(str(result.latitde) + "," + str(result.longitude) + "," + str(result.speed) + "," + str(result.altitude) + "," + result.time)
                        self.writeCSVIperf(csv, result.client_sent, "client_sent")
                        self.writeCSVIperf(csv, result.client_receive, "client_receive")
                        self.writeCSVIperf(csv, result.client_summary, "client_summary")
                        self.writeCSVIperf(csv, result.server_sent, "server_sent")
                        self.writeCSVIperf(csv, result.server_receive, "server_receive")
                        self.writeCSVIperf(csv, result.server_sumary, "server_sumary")
                        csv.write("," + str(result.ping) + "\n")
        except Exception as e:
            for line in traceback.format_exc().splitlines():
                syslog.syslog(line)

    def run(self):
        try:
            self.window = sg.Window("Network Tester", self.layout, no_titlebar=True, finalize=True)
            self.fping = FPing(self.window, "callback-fping", ip=self.config['FPing']['server'], path=self.config['FPing']['binary'], interval=int(self.config['FPing']['Interval']))
            self.iperf = IPerf3(self.window, "callback-iperf", client=self.config['IPerf3']['server'], path=self.config['IPerf3']['binary'], time=int(self.config['IPerf3']['time']), delay=int(self.config['IPerf3']['interval']), bidir=True, udp=True, bitrate="8M")
            self.gps = UpdateGPS(self.window, "callback-gps")
            self.enabled_button_color = self.window.ButtonColor[1]
            c = tuple(int(self.enabled_button_color.lstrip("#")[i: i + 2], 16) for i in (0, 2, 4))
            self.disabled_button_color = "#{:02x}{:02x}{:02x}".format(int(c[0] / 2), int(c[1] / 2), int(c[2] / 2))
            self.window["btn_start"].update(disabled=False)
            self.window["btn_stop"].update(disabled=True, button_color=self.disabled_button_color)
            self.window["btn_speed_4"].update(disabled=True, button_color=self.disabled_button_color)
        except Exception as e:
            for line in traceback.format_exc().splitlines():
                syslog.syslog(line)

        # Run the Event Loop
        while True:
            try:
                event, values = self.window.read()
                if event == "btn_exit" or event == sg.WIN_CLOSED:
                    try:
                        if self.fping.enable is True:
                            self.fping.disabled()
                        if self.iperf.enable is True:
                            self.iperf.disabled()
                        if self.gps.enable is True:
                            self.gps.disabled()
                        if self.log_file is not None:
                            tftpc: tftpy.TftpClient = tftpy.TftpClient(self.config['Tftp']['server'])
                            tftpc.upload(self.config['Tftp']['directory'] + "/" + self.log_file, self.config['Log']['directory'] + "/" + self.log_file)
                            os.remove(self.config['Log']['directory'] + "/" +  self.log_file)
                            self.log_file = None
                        break
                    except Exception as e:
                        for line in traceback.format_exc().splitlines():
                            syslog.syslog(line)
                        self.log_file = None
                elif event == "btn_start":
                    try:
                        self.log_file = "GpsWidget-%s.csv" % (datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
                        self.writeCSV(None, True)
                        self.history.clear()
                        self.fping.enabled()
                        self.iperf.enabled()
                        self.gps.enabled()
                        self.window["btn_start"].update(disabled=True, button_color=self.disabled_button_color)
                        self.window["btn_stop"].update(disabled=False, button_color=self.enabled_button_color)
                    except Exception as e:
                        for line in traceback.format_exc().splitlines():
                            syslog.syslog(line)
                elif event == "btn_stop":
                    try:
                        self.fping.disabled()
                        self.iperf.disabled()
                        self.gps.disabled()
                        self.window["btn_start"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_stop"].update(disabled=True, button_color=self.disabled_button_color)
                        self.window["text_gps_latitude"].update("N/A")
                        self.window["text_gps_longitude"].update("N/A")
                        self.window["text_gps_vitesse"].update("N/A")
                        self.window["text_gps_altitude"].update("N/A")
                        self.window["text_gps_horloge"].update("N/A")
                        self.window["text_client_send"].update("N/A")
                        self.window["text_client_recv"].update("N/A")
                        self.window["text_server_send"].update("N/A")
                        self.window["text_server_recv"].update("N/A")
                        self.window["text_ping"].update("N/A")
                        tftpc: tftpy.TftpClient = tftpy.TftpClient(self.config['Tftp']['server'])
                        tftpc.upload(self.config['Tftp']['directory'] + "/" + self.log_file, self.config['Log']['directory'] + "/" + self.log_file)
                        os.remove(self.config['Log']['directory'] + "/" +  self.log_file)
                        self.log_file = None
                    except Exception as e:
                        for line in traceback.format_exc().splitlines():
                            syslog.syslog(line)
                        self.log_file = None
                elif event == "btn_speed_4":
                    try:
                        self.window["btn_speed_4"].update(disabled=True, button_color=self.disabled_button_color)
                        self.window["btn_speed_8"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_16"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_32"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_64"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_max"].update(disabled=False, button_color=self.enabled_button_color)
                        self.iperf.cmdline(client=self.config['IPerf3']['server'], path=self.config['IPerf3']['binary'], time=int(self.config['IPerf3']['time']), bidir=True, udp=True, bitrate="8M")
                    except Exception as e:
                        for line in traceback.format_exc().splitlines():
                            syslog.syslog(line)
                elif event == "btn_speed_8":
                    try:
                        self.window["btn_speed_4"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_8"].update(disabled=True, button_color=self.disabled_button_color)
                        self.window["btn_speed_16"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_32"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_64"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_max"].update(disabled=False, button_color=self.enabled_button_color)
                        self.iperf.cmdline(client=self.config['IPerf3']['server'], path=self.config['IPerf3']['binary'], time=int(self.config['IPerf3']['time']), bidir=True, udp=True, bitrate="16M")
                    except Exception as e:
                        for line in traceback.format_exc().splitlines():
                            syslog.syslog(line)
                elif event == "btn_speed_16":
                    try:
                        self.window["btn_speed_4"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_8"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_16"].update(disabled=True, button_color=self.disabled_button_color)
                        self.window["btn_speed_32"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_64"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_max"].update(disabled=False, button_color=self.enabled_button_color)
                        self.iperf.cmdline(client=self.config['IPerf3']['server'], path=self.config['IPerf3']['binary'], time=int(self.config['IPerf3']['time']), bidir=True, udp=True, bitrate="32M")
                    except Exception as e:
                        for line in traceback.format_exc().splitlines():
                            syslog.syslog(line)
                elif event == "btn_speed_32":
                    try:
                        self.window["btn_speed_4"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_8"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_16"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_32"].update(disabled=True, button_color=self.disabled_button_color)
                        self.window["btn_speed_64"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_max"].update(disabled=False, button_color=self.enabled_button_color)
                        self.iperf.cmdline(client=self.config['IPerf3']['server'], path=self.config['IPerf3']['binary'], time=int(self.config['IPerf3']['time']), bidir=True, udp=True, bitrate="64M")
                    except Exception as e:
                        for line in traceback.format_exc().splitlines():
                            syslog.syslog(line)
                elif event == "btn_speed_64":
                    try:
                        self.window["btn_speed_4"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_8"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_16"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_32"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_64"].update(disabled=True, button_color=self.disabled_button_color)
                        self.window["btn_speed_max"].update(disabled=False, button_color=self.enabled_button_color)
                        self.iperf.cmdline(client=self.config['IPerf3']['server'], path=self.config['IPerf3']['binary'], time=int(self.config['IPerf3']['time']), bidir=True, udp=True, bitrate="128M")
                    except Exception as e:
                        for line in traceback.format_exc().splitlines():
                            syslog.syslog(line)
                elif event == "btn_speed_max":
                    try:
                        self.window["btn_speed_4"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_8"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_16"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_32"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_64"].update(disabled=False, button_color=self.enabled_button_color)
                        self.window["btn_speed_max"].update(disabled=True, button_color=self.disabled_button_color)
                        self.iperf.cmdline(client=self.config['IPerf3']['server'], path=self.config['IPerf3']['binary'], time=int(self.config['IPerf3']['time']), bidir=True, udp=True)
                    except Exception as e:
                        for line in traceback.format_exc().splitlines():
                            syslog.syslog(line)
                elif event == "callback-iperf":
                    try:
                        result = values["callback-iperf"]["end"]
                        ipr: IPerfResult = IPerfResult(float(re.sub("[^\d\.\-]", "", self.window["text_gps_latitude"].get())), float(re.sub("[^\d\.\-]", "", self.window["text_gps_longitude"].get())), float(re.sub("[^\d\.\-]", "", self.window["text_gps_vitesse"].get())), float(re.sub("[^\d\.\-]", "", self.window["text_gps_altitude"].get())), self.window["text_gps_horloge"].get(), self.getiperfdata(result["sum_sent"]), self.getiperfdata(result["sum_received"]), self.getiperfdata(result["sum"]), self.getiperfdata(result["sum_sent_bidir_reverse"]), self.getiperfdata(result["sum_received_bidir_reverse"]), self.getiperfdata(result["sum_bidir_reverse"]), float(re.sub("[^\d\.\-]", "", self.window["text_ping"].get())))
                        self.writeCSV(ipr)
                        self.window["text_client_send"].update(self.bytes_per_seconds(result["sum_sent"]["bits_per_second"], result["sum_sent"]["seconds"]))
                        self.window["text_client_recv"].update(self.bytes_per_seconds(result["sum_received"]["bits_per_second"], result["sum_received"]["seconds"]))
                        self.window["text_server_send"].update(self.bytes_per_seconds(result["sum_sent_bidir_reverse"]["bits_per_second"],result["sum_sent_bidir_reverse"]["seconds"]))
                        self.window["text_server_recv"].update(self.bytes_per_seconds(result["sum_received_bidir_reverse"]["bits_per_second"],result["sum_received_bidir_reverse"]["seconds"]))
                    except Exception as e:
                        for line in traceback.format_exc().splitlines():
                            syslog.syslog(line)
                elif event == "callback-fping":
                    try:
                        self.window["text_ping"].update(values["callback-fping"]["avg"] + "ms")
                    except Exception as e:
                        for line in traceback.format_exc().splitlines():
                            syslog.syslog(line)
                elif event == "callback-gps":
                    try:
                        response: gpsd.GpsResponse = values["callback-gps"]
                        self.window["text_gps_latitude"].update(str(response.lat))
                        self.window["text_gps_longitude"].update(str(response.lon))
                        self.window["text_gps_vitesse"].update(str(response.hspeed) + "m/s")
                        self.window["text_gps_altitude"].update("%.*fm" % (2, response.alt))
                        self.window["text_gps_horloge"].update(str(response.get_time(True)))
                    except Exception as e:
                        for line in traceback.format_exc().splitlines():
                            syslog.syslog(line)
            except Exception as e:
                for line in traceback.format_exc().splitlines():
                    syslog.syslog(line)
        self.window.close()


if __name__ == "__main__":
    try:
        configfile = os.path.dirname(__file__) + "/" + os.path.splitext(os.path.basename(__file__))[0] + ".ini" 
        config = configparser.ConfigParser()
        config.read(configfile)
        if 'Default' not in config:
            config['Default'] = {}
        if 'Theme' not in config['Default']:
            config['Default']['Theme'] = "DarkBlue3"
        if 'Tftp' not in config:
            config['Tftp'] = {}
        if 'Server' not in config['Tftp']:
            config['Tftp']['Server'] = "10.139.241.86"
        if 'GpsWidget' not in config['Tftp']:
            config['Tftp']['Directory'] = "/GpsWidget"
        if 'Log' not in config:
            config['Log'] = {}
        if 'Directory' not in config['Log']:
            config['Log']['Directory'] = os.environ.get('HOME') + "/Desktop/GpsWidget.log"
        if 'FPing' not in config:
            config['FPing'] = {}
        if 'Interval' not in config['FPing']:
            config['FPing']['Interval'] = "1"
        if 'Server' not in config['FPing']:
            config['FPing']['Server'] = "10.139.65.50"
        if 'Binary' not in config['FPing']:
            config['FPing']['Binary'] = FindExec("fping")
        if 'IPerf3' not in config:
            config['IPerf3'] = {}
        if 'Interval' not in config['IPerf3']:
            config['IPerf3']['Interval'] = "10"
        if 'time' not in config['IPerf3']:
            config['IPerf3']['time'] = "2"
        if 'Server' not in config['IPerf3']:
            config['IPerf3']['Server'] = "10.139.65.50"
        if 'Binary' not in config['IPerf3']:
            config['IPerf3']['Binary'] = FindExec("iperf3")
        with open(configfile, 'w') as cfg:
            config.write(cfg)
    except Exception as e:
        sg.popup_error(traceback.format_exc(), title="Erreur de configuration")
        for line in traceback.format_exc().splitlines():
            syslog.syslog(line)
        quit()
    try:
        syslog.openlog(logoption=syslog.LOG_PID)
        if not os.path.isdir(config['Log']['Directory']):
            os.makedirs(config['Log']['Directory'])
        app = MainWindow(config)
        app.run()
    except Exception as e:
        sg.popup_error(traceback.format_exc(), title="Erreur")
        for line in traceback.format_exc().splitlines():
            syslog.syslog(line)
