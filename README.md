# HomeNet

Decentralized, secure, in-the-home communication with IoT devices with support for IEEE 802.15.4 based network-communication.

Consider this a return from my programming hiatus. Hope you guys will love this as much as I loved making this.

## So what is it?

At the core, this is a simple P2P (ad-hoc style) mesh network created with the help of [Openthread](https://openthread.io/), an open source version of the mesh networking system [Thread](threadgroup.org).

Thread is a low-power, low latency mesh network technology designed for Internet of Things (IoT) devices. It enabled devices to communicate **directly** (keep in mind very important) with each other, forming a resilient network with multiple paths to reach each node.

In simpler words, Thread is a resilient network designed to handle potentially harmful changes, reconfiguring and adapting based on the given environment. It is meant for smaller devices such as the ESP32C6, a key SoC in this project.

## Project Roadmap

* [ ] Create basic messaging w/ commands
* [ ] Allow the saving of clients like phone contacts
* [ ] Allow communication with these saved clients like DMs
* [ ] Establish a method to ensure the security of the connection
* [ ] (Maybe) Make an application that communicates with the ESP over BLE to send messages

## Installation

Here are some pre-requisites if you ever consider building a small HomeNet mesh:

* ESP32C6 (possibly ESP32C5) based microcontroller(s)
* A safe, clean environment to place devices in
* A device to compile and flash the code with

I would start off with... (TBA)

## Acknowledgements

* OpenThread
* Espressif
* M5Stack

Made with :heart: by @dj1ch
