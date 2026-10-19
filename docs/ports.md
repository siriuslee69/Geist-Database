# Geist ports

The project reserves **47650–47659** for Geist services. This is the
workspace's allocation, not an IANA registration or an instruction to open
the whole range in a firewall.

| UDP port | Service |
| --- | --- |
| 47650–47654 | Reserved for future Geist services |
| 47655 | Store (`geistd`, monitor store); a transparent forwarder may expose this same endpoint on another host |
| 47656 | Message relay (`geist-relayd`, monitor relay) |
| 47657 | Request router (`geist-routed`) |
| 47658–47659 | Reserved for future Geist services |

The device deployment opens only UDP 47655 and UDP 47656, in NixOS and in
the hosting provider's firewall. No TCP port is needed for communication
between devices. Desktop WebUI traffic stays local to the PC; Android uses
a local JNI bridge. Neither carries device messages around Geist.
