import socket
import os
import time
import sys
import struct
import select

timer = time.time

ICMP_ECHO = 8
ICMP_ECHOREPLY = 0
CODE = 0


def calculate_checksum(packet):

	countTo = (len(packet) // 2) * 2

	count = 0
	sum = 0

	while count < countTo:
		if sys.byteorder == "little":
			loByte = packet[count]
			hiByte = packet[count + 1]
		else:
			loByte = packet[count + 1]
			hiByte = packet[count]
		sum = sum + (hiByte * 256 + loByte)
		count += 2

	if countTo < len(packet):
		sum += packet[count]

	# sum &= 0xffffffff

	sum = (sum >> 16) + (sum & 0xffff)  # adding the higher order 16 bits and lower order 16 bits
	sum += (sum >> 16)
	answer = ~sum & 0xffff
	answer = socket.htons(answer)

	return answer


def is_valid_ip(hostname_ip):
	ip_parts = hostname_ip.strip().split('.')
	if ip_parts != 4:
		return False
	for part in ip_parts:
		try:
			if int(part) < 0 or int(part) > 255:
				return False

		except ValueError:
			return False

	return True


def to_ip(hostname):
	if is_valid_ip(hostname):
		return hostname
	return socket.gethostbyname(hostname)


class Ping:

	def __init__(self, destination_server, count_of_packets, timeout_in_ms, packet_size):
		self.destination_server = destination_server
		self.count_of_packets = count_of_packets
		self.timeout_in_ms = timeout_in_ms
		self.packet_size = packet_size
		self.identifier = os.getpid() & 0xffff
		self.seq_no = 0
		try:
			self.destination_ip = to_ip(self.destination_server)

		except socket.gaierror as e:
			self.print_unknown_host(e)
			sys.exit()

	def print_start(self):

		print("PYTHON-PING {} ({}): {} data bytes".format(self.destination_server, self.destination_ip, self.packet_size))

	def start_ping(self):

		try:
			while self.count_of_packets > 0:
				self.create_socket()
				self.count_of_packets -= 1

		except KeyboardInterrupt:  # handle Ctrl+C
			print("exit")

	def create_socket(self):

		try:
			icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("ICMP"))

		except socket.error as err:
			if err.errno == 1:
				print("Operation not permitted: ICMP messages can only be sent from a process running as root")
			else:
				print("Error: {}".format(err))

			sys.exit()

		self.print_start()
		time_values = self.send_icmp_request(icmp_socket)

		if time_values is None:
			return

		send_time, start_of_wait = map(float, time_values)
		receive_time = self.receive_icmp_reply(icmp_socket)

		delay = (receive_time - send_time) * 1000.00
		print("Packet {}; Delay: {}".format(self.seq_no, delay))
		self.seq_no += 1

	def send_icmp_request(self, icmp_socket):

		checksum = 0
		startvalue = 65
		header = struct.pack("!BBHHH", ICMP_ECHO, CODE, checksum, self.identifier, self.seq_no)

		payload = []
		for i in range(startvalue, startvalue + self.packet_size):
			payload.append(i & 0xff)

		data = bytes(payload)

		checksum = calculate_checksum(header + data)
		header = struct.pack("!BBHHH", ICMP_ECHO, CODE, checksum, self.identifier, self.seq_no)

		packet = header + data

		send_time = timer()
		try:
			icmp_socket.sendto(packet, (self.destination_server, 1))
			start_of_wait = timer()

		except socket.error as err:
			print("General error: %s", err)
			icmp_socket.close()
			return None

		return send_time, start_of_wait

	def receive_icmp_reply(self, icmp_socket):

		timeout = self.timeout_in_ms/1000  # converting timeout to s

		while True:

			inputready, _, _ = select.select([icmp_socket], [], [], timeout)
			receive_time = timer()

			if not inputready:  # timeout
				print("Request timed out")
				sys.exit(-1)

			packet_data, address = icmp_socket.recvfrom(2048)

			return receive_time


def ping(destination_server, timeout=1000, count=4, packet_size=55):
	p = Ping(destination_server, count, timeout, packet_size)
	p.start_ping()


ping("google.com", packet_size=100)
