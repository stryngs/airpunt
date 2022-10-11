# airpunt
airpunt deauthenticates a given target MAC address and then tracks the associated handshake when the MAC address rejoins the wireless network.

airpunt is a tool aimed at assisting the user in viewing a given wireless scenario through a decryption tool such as [pyDot11](https://github.com/stryngs/pyDot11) or [Airtun-ng](https://www.aircrack-ng.org/doku.php?id=airtun-ng), but in a sane manner so that after the initial deauthentication, subsequent deauthentications are only sent if there is a new handshake that was somehow missed.

## Setup
```
git clone https://github.com/stryngs/packetEssentials
git clone https://github.com/stryngs/pyDot11
python3 -m pip install pbkdf2
python3 -m pip install pycryptodomex
python3 -m pip install rc4
python3 -m pip install scapy
python3 -m pip install pyDot11/RESOURCEs/pyDot11*
python3 -m pip install packetEssentials/RESOURCEs/packetEssentials*
```

## Usage
```
python3 ./airpunt.py -b aa:bb:cc:dd:ee:ff -i wlan0 -t 11:22:33:44:55:66
```
