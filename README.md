# airpunt
airpunt deauthenticates a given target MAC address and then tracks the associated handshake when the MAC address rejoins the wireless network.

airpunt is a tool aimed at assisting the user in viewing a given wireless scenario through a decryption tool such as [pyDot11](https://github.com/stryngs/pyDot11) or [Airtun-ng](https://www.aircrack-ng.org/doku.php?id=airtun-ng), but in a sane manner so that after the initial handshake capture, subsequent deauthentications are not sent.

## Setup
````bash
python3 -m venv env
source env/bin/activate
python3 -m pip install RESOURCEs/packetEssentials-2.0.tar.gz
python3 -m pip install RESOURCEs/scapy-2.5.0.tar.gz
````

## Usage
````bash
python3 ./airpunt.py -b aa:bb:cc:dd:ee:ff -i wlan0 -t 11:22:33:44:55:66
````
