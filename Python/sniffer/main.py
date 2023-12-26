#Run in Admin mode
import socket
import os

HOST = '192.168.86.247'

def main(write_to_file=False):
    socketProtocol = rawSocket()
    sniffer = snifferFunc(socketProtocol)
    OSStuff(sniffer, write_to_file)

def rawSocket():
    if os.name == 'nt':
        socketProtocol = socket.IPPROTO_IP
    else:
        socketProtocol = socket.IPPROTO_ICMP
    return socketProtocol

def snifferFunc(socketProtocol):
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socketProtocol)
    sniffer.bind((HOST, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return sniffer

def OSStuff(sniffer, write_to_file=False):
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    finalWork = sniffer.recvfrom(65565)
    packet = finalWork[0]
    packet = str(packet)[2:-1]

    result = f'{packet}\n\nis the frame read from\n\n{finalWork[1][0]}'

    if write_to_file:
        write_to_txt(result)
    else:
        print(result)

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

def write_to_txt(result):
    with open("sniffer_results.txt", "a") as file:
        file.write(result + "\n\n" + "=" * 40 + "\n\n")

if __name__ == "__main__":
    try:
        choice = int(input("Do you want to:\n1)\tRun once\n2)\tLoop the program multiple times\n\t"))
        if choice == 1:
            loop = 1
        elif choice == 2:
            loop = int(input("How many times to repeat?\t"))
        write_to_file = input("Do you want to write results to a file? (yes/no)\t").lower() == 'yes'

        for i in range(loop):
            main(write_to_file)

    except ValueError:
        print("Invalid input. Please enter a valid choice and number of repetitions.")
    except PermissionError:
        print("Retry running the program with elevated privileges.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")