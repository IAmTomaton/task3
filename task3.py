import argparse
import socket
import threading
import re


TIMEOUT = 0
dns = b'\xAA\xAA\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01'
TCP = [('DNS', dns),
	   ('SMTP', b'EHLO dima.example.org\r\n'),
	   ('HTTP', b'GET / HTTP/1.1\r\nHost: google.com\r\n\r\n'),
	   ('POP3', b'USER dima\r\n')]
UDP = [('DNS', dns),
	   ('SMTP', ('\x1b' + 39 * '\0' + 8 * '\x11').encode('utf-8'))]


def parse_protocol(data):
	if data.startswith(b'HTTP'):
		return 'HTTP'
	elif re.match(br'[0-9]{3}', data[:3]):
		return 'SMTP'
	elif data.startswith(b'\xAA\xAA'):
		return 'DNS'
	elif data.startswith(b'+'):
		return 'POP3'
	elif (8 * '\x11').encode('utf-8') in data:
		return 'SMTP'
	else:
		return ''


def scan_tcp(ip, port):
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
		sock.settimeout(TIMEOUT)

		try:
			sock.connect((ip, port))
		except socket.error:
			return None

		for p in TCP:
			try:
				sock.sendall(p[1])
				recv = sock.recv(1024)
				protocol = parse_protocol(recv)
				
				if protocol == p[0]:
					return protocol
			except socket.error:
				pass
	return ''


def scan_udp(ip, port):
	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
		sock.settimeout(TIMEOUT)

		try:
			sock.sendto(b'hi port', (ip, port))
			recv, addr = sock.recvfrom(1024)
			if data.startswith(bytes([3, 3])):
				return None
		except socket.timeout:
			pass
		except socket.error:
			return None
		
		for p in UDP:
			try:
				sock.sendto(p[1], (ip, port))
				recv = sock.recv(1024)
				protocol = parse_protocol(recv)

				if protocol == p[0]:
					return protocol
			except socket.error:
				pass
	return ''


def test_ports(ip, ports, protocol, tester):
	for port in ports:
		result = tester(ip, port)
		if result is None:
			print(f'IP: {ip} PORT: {port} {protocol} порт закрыт.')
		elif len(result) > 0:
			print(f'IP: {ip} PORT: {port} {protocol} порт открыт. Протокол: {result}.')
		elif len(result) == 0:
			print(f'IP: {ip} PORT: {port} {protocol} порт открыт. Протокол определить не удалось.')


def test(ip, ports, tcp, udp, threads_count):
	l = len(ports)
	threads_count = min(threads_count, l)
	count = l // threads_count

	threads = []

	extra = l - count * threads_count

	for t in range(threads_count):
		add = 1 if extra > 0 else 0
		extra -= 1
		ports_count = count + add
		if tcp:
			thread = threading.Thread(target=test_ports, args=(ip, ports[t * ports_count: (t + 1) * ports_count], 'TCP', scan_tcp))
			threads.append(thread)
			thread.start()
		if udp:
			thread = threading.Thread(target=test_ports, args=(ip, ports[t * ports_count: (t + 1) * ports_count], 'UDP', scan_udp))
			threads.append(thread)
			thread.start()

	for thread in threads:
		thread.join()


def arg_parser():
	parser = argparse.ArgumentParser(allow_abbrev=True)
	parser.add_argument('-i', '--ip', type=str, default='', help='IP')
	parser.add_argument('-f', '--first', type=int, help='Первый порт')
	parser.add_argument('-l', '--last', type=int, help='Последний порт')
	parser.add_argument('-p', '--port', type=int, action='append', help='Порт')
	parser.add_argument('-u', '--udp', action='store_true', help='Протокол')
	parser.add_argument('-t', '--tcp', action='store_true', help='Протокол')
	parser.add_argument('-c', '--threads_count', type=int, default=10, help='Максимальное число потоков')
	parser.add_argument('-o', '--timeout', type=float, default=0.1, help='Таймаут')

	return parser


def main():
	global TIMEOUT

	args = arg_parser().parse_args()

	TIMEOUT = args.timeout

	ports = []

	if args.first and args.last:
		ports = list(range(args.first, args.last + 1))
	elif args.first:
		ports = list(range(args.first, 65535 + 1))
	elif args.last:
		ports = list(range(1, args.last + 1))
	if args.port:
		for p in args.port:
			if p not in ports: ports.append(p)
	
	test(args.ip, ports, args.tcp, args.udp, args.threads_count)


if __name__ == '__main__':
    main()
