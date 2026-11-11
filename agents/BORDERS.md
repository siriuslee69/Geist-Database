# Borders

job: read, write, check and seal data on THIS machine, and decide who may do what with it. If it works with the network cable pulled, it belongs here.
not its job: sockets, peers, handshakes, sync between machines -> Nebel. Key agreement and wire formats -> Bifrost. Screens -> the apps.
never imports: bifrost, nebel, protocols/ame, protocols/dac
may be imported by: Nebel, the apps

Geist never learns where a caller sits. The caller says who is asking and hands over
keys; Geist answers yes or no. Bytes that must come from elsewhere arrive through a
provider hook (`gSidecarProvider`) or as a log chunk (`boxcopy`).
