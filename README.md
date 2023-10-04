# npcap_wrapper

Requires installing [npcap](https://npcap.com/). An executable is provided in ```npcap_sdk/npcap-1.76.exe```.

## Directories to include
- ```npcap_sdk/include```
- ```/include```

## Library folders
- ```npcap_sdk/lib/```

## Libraries to link
- Packet
- wpcap

## Building the Executables
- ```mkdir build```
- ```cd build```
- ```cmake ..```
- ```cmake --build .```
- ```cd Debug``` The executables will be here.
