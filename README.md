![GitHub contributors](https://img.shields.io/github/contributors/dj1ch/HomeNet)
![GitHub forks](https://img.shields.io/github/forks/dj1ch/HomeNet)
![GitHub Repo stars](https://img.shields.io/github/stars/dj1ch/HomeNet)
![GitHub Repo stars](https://img.shields.io/github/stars/dj1ch/HomeNet)
![GitHub Issues](https://img.shields.io/github/issues/dj1ch/HomeNet)
![GitHub License](https://img.shields.io/github/license/dj1ch/HomeNet)

<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/dj1ch/HomeNet">
    <img src="images/logo.png" alt="Logo" width="400" height="300">
  </a>

  <h3 align="center">HomeNet</h3>

  <p align="center">
    Decentralized, secure, in-the-home communication with IoT devices with support for IEEE 802.15.4 based network-communication.
    <br />
    <a href="https://github.com/dj1ch/HomeNet"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://youtu.be/0GrTWAWUdIw">View Demo</a>
    ·
    <a href="https://github.com/dj1ch/HomeNet/issues">Report Bug</a>
    ·
    <a href="https://github.com/dj1ch/HomeNet/issues">Request Feature</a>
  </p>
</p>



<!-- TABLE OF CONTENTS -->
## Table of Contents

* [About the Project](#about-the-project)
  * [Built With](#built-with)
* [Getting Started](#getting-started)
  * [Prerequisites](#prerequisites)
  * [Installation](#installation)
* [Usage](#usage)
* [Roadmap](#roadmap)
* [Contributing](#contributing)
* [License](#license)
* [Contact](#contact)
* [Acknowledgements](#acknowledgements)

<!-- ABOUT THE PROJECT -->
## About The Project

At the core, this is a simple mesh network created with the help of [OpenThread](https://openthread.io/), an open source version of the mesh networking system [Thread](threadgroup.org).

Thread is a low-power, low latency mesh network technology designed for Internet of Things (IoT) devices. It enabled devices to communicate **directly** (keep in mind very important) or through multiple paths with each other, forming a resilient network with multiple methods to reach each node.

Here is a somewhat simplified example of how it might look:

```md
Device 1 <-> Device 2
  ^            ^
  |            |
  v            |
  Device 3 <----
```

In simpler words, Thread is a resilient network designed to handle potentially harmful changes, reconfiguring and adapting based on the given environment. For example, if a node were to suddenly go down, the network will reconfigure to fix this issue. It is meant for smaller devices such as the ESP32C6, a key SoC in this project.

For example our network might reconfigure to look something like this:

```md
Device 1 <-> Device 2
```

We use this mesh network to ensure that a secure medium is established between devices for the sake of security, a core idea of this project.

Meshes are naturally a lot more secure than regular networks. Their structures, like said before, have no sort of centralization, and can configure at will. There is a lot of redundancy, having the posssibility of multiple routers, commissioners, children, etc. Although this might seem inconvenient, it eliminates the reliance of one device, which could serve as a point of failure. This allows our network to prevail under **most** circumstances.

In this secure mesh, we allow our devices to communicate with one another directly over [IPv6](https://www.cisco.com/c/en/us/solutions/ipv6/overview.html), the latest, though probably not the most convenient networking protocol to use. Addresses tend to be lengthier which allows undecillions(billion billion billions) of devices to have unique devices, while [IPv4](https://bluecatnetworks.com/glossary/what-is-ipv4/)(the one that you're used to using) can only really hold up to a couple billions.

The real protocols behind the 'texting' here isn't anything new, rather it takes advantage of [UDP](https://www.cloudflare.com/learning/ddos/glossary/user-datagram-protocol-udp/), a packet often used for data transfer, whether it be videos, DNS lookups, or online gaming (yes, online gaming). Although one could argue that TCP is much more secure, I find UDP much more easier to use with the Openthread API, and more well established.

**TLDR: HomeNet is a special type of network called a mesh network, with secure messaging using UDP, often used for stuff like online games.**

### Built With

* [esp-idf@v5.3](https://github.com/espressif/esp-idf/tree/v5.3)
* [M5NanoC6](https://shop.m5stack.com/products/m5stack-nanoc6-dev-kit) or any other ESP32 with support for OpenThread

<!-- GETTING STARTED -->
## Getting Started

To get a local copy up and running follow these simple steps.

### Prerequisites

### Installation

1. Clone the repo

```sh
git clone https://github.com/dj1ch/HomeNet.git
```

2. Install `esp-idf`: Follow [documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/#installation) and install version 5.3.

3. Set board target

```sh
idf.py set-target <your_esp32*_board>
```

If it asks that you delete the build directory or `sdkconfig`, you will need to do that to compile for that board. 

4. Build the project

```sh
idf.py build
```

5. Flash to your ESP32(replace `PORT` with the port connected to your ESP32)

```sh
idf.py -p PORT flash
```

or you can run

```sh
idf.py flash
```

<!-- USAGE EXAMPLES -->
## Usage

Here are the commands that you can use:

* `set_nickname` Sets the nickname of a peer (WIP)
* `get_nickname` Gets the peer's nickname based on their IPv6 address (WIP)
* `get_ipv6` Gets the peer's IPv6 address bassed on nickname (WIP)
* `send_message` Sends a message to a peer manually
* `configure_network` Configures **one** of your devices as the leader of the mesh network, though this doesn't really change anything about message sending
* `configure_joiner` Configures **any** device as a joiner, meaning that it joins the mesh created by the device that ran the `configure_network` command
* `turn_on_led` Turns on the onboard LED (must be configured)
* `turn_off_led` Turns off the onboard LED (must be configured)
* `get_nvs_entries` Lists all NVS entries
* `clear_nvs_entries` Clears NVS entries (if any)

<!-- ROADMAP -->
## Roadmap

As of now I would like to implement/am in the progress of implementing:

* [x] Create basic messaging w/ commands
* [x] Create custom method for anyone to advertise their presence to other instances of HomeNet
* [x] Allow the saving of clients like phone contacts
* [ ] Allow direct communication with these saved clients like DMs
* [x] Establish a method to ensure the security of the connection
* [ ] Rewrite UDP communication using custom receivers, transmitters, etc
  * [x] Custom transmitter
  * [ ] Custom receiver
* [ ] Make documentation simpler for other audiences (may need to reach out)
* [ ] (Maybe) Make an application that communicates with the ESP over BLE to send messages

See the [open issues](https://github.com/dj1ch/HomeNet/issues) for a list of proposed features (and known issues).

<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.

<!-- CONTACT -->
## Contact

dj1ch - tg.1ch0712@gmail.com

Project Link: [https://github.com/dj1ch/HomeNet](https://github.com/dj1ch/HomeNet)

<!-- ACKNOWLEDGEMENTS -->
## Acknowledgements

* [Espressif](https://github.com/espressif/)
* [Espressif OpenThread fork](https://github.com/espressif/openthread)
* [ESP32 IEEE 802.15.4 Example](https://github.com/espressif/esp-idf/blob/master/examples/ieee802154/ieee802154_cli/main/esp_ieee802154_cli.c)
* [ESP32 Advanced Console example](https://github.com/espressif/esp-idf/tree/v5.3/examples/system/console/advanced)
* [ESP32 Basic Console example](https://github.com/espressif/esp-idf/tree/v5.3/examples/system/console/basic)
* [ot-send Example](https://github.com/UCSC-ThreadAscon/ot-send)
* [ot-receive Example](https://github.com/UCSC-ThreadAscon/ot-receive)
* [Nano Framework Interpreter](https://github.com/nanoframework/nf-interpreter)
* And many more...!

## Additional learning

* [Thread Primer: What is Thread?](https://openthread.io/guides/thread-primer)
* [What is a mesh network?](https://support.google.com/googlenest/answer/7182746?hl=en)
* [An introduction to IEEE STD 802.15.4](https://ieeexplore.ieee.org/document/1655947)
* [Introduction of IEEE 802.15.4 Technology](https://www.geeksforgeeks.org/introduction-of-ieee-802-15-4-technology/)
* [IEEE 802.15.4 Standard: a tutorial / primer](https://www.electronics-notes.com/articles/connectivity/ieee-802-15-4-wireless/basics-tutorial-primer.php)
* [OpenThread - Espressif Documentation](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-guides/openthread.html)

Made with :heart: by [@dj1ch](https://github.com/dj1ch)
