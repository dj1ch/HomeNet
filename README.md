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
    <img src="https://raw.githubusercontent.com/dj1ch/HomeNet/refs/heads/main/images/logo.png" alt="Logo" width="400" height="300">
  </a>

  <h3 align="center">HomeNet</h3>

  <p align="center">
    Decentralized, secure, in-the-home communication with IoT devices with support for IEEE 802.15.4 based network-communication.
    <br />
    <a href="https://github.com/dj1ch/HomeNet"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://youtu.be/-zFOi41-QDw">View Demo</a>
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

Speaking of communication, the real protocols behind the 'texting' here in this mesh isn't anything new, rather it takes advantage of [UDP](https://www.cloudflare.com/learning/ddos/glossary/user-datagram-protocol-udp/), a packet often used for data transfer, whether it be videos, DNS lookups, or online gaming (yes, online gaming). Although one could argue that TCP is much more secure, I find UDP much more easier to use with the Openthread API, and more well established.

A UDP 'connection' may look like this:

```md
          (request)
1. Sender <-------- Receiver
          (response)
2. Sender --------> Receiver
          (response)
3. Sender --------> Receiver
          (response)
4. Sender --------> Receiver
```

So the messages here can only really be seen in the mesh, if they're ever received. Lucky for us, devices in this mesh are programmed to handle the data received, as well as sending it.

**TLDR: HomeNet is a special type of network called a mesh network, with secure messaging using UDP, often used for stuff like online games.**

**Before you continue any further, please not only consider contributing to this project, but also [Hack Club](https://hackclub.com/), who supported me throughout development and kept me motivated to continue this project. Their funding allowed me to purchase more hardware without the risk of this being a potential financial burden.**

Look interesting? Let's go to [Prerequisites](#prerequisites).

### Built With

* [esp-idf@v5.3](https://github.com/espressif/esp-idf/tree/v5.3)
* [M5NanoC6](https://shop.m5stack.com/products/m5stack-nanoc6-dev-kit) or any other ESP32 with support for OpenThread

<!-- GETTING STARTED -->
## Getting Started

To get a local copy up and running follow these simple steps.

### Prerequisites

### Supported Hardware

* `ESP32C6-*`
* `ESP32C5-*`
* `ESP32H2-*`

I highly recommend getting an [M5NanoC6](https://shop.m5stack.com/products/m5stack-nanoc6-dev-kit), [ESP32H2-*](https://www.amazon.com/Espressif-ESP32-H2-DevKitM-1-N4-Development-Board/dp/B0BWM83LMF), or ESP32C5-* (whenever that comes out) as these are devices not only supported by `esp-idf` but also `Openthread`. You can probably find them cheaper elsewhere but usually I go with well known sellers as they are often much more trustworthy than a random website and/or person.

### Installation

1. Clone the repo

```sh
git clone https://github.com/dj1ch/HomeNet.git
```

2. Install `esp-idf`: Follow [documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/#installation) and install version 5.3, or you can install the [VSCode extension](https://github.com/espressif/vscode-esp-idf-extension).

3. Set board target

```sh
idf.py set-target <your_esp32*_board>
```

If it asks that you delete the build directory or `sdkconfig`, you will need to do that to compile for that board.

If you're using the VSCode extension you'll need to click `Open ESP-IDF Terminal` beforehand to create an `esp-idf` shell.

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

If you want to make things easier on yourself, you can use the VSCode Extension to select your COM Port with button `Select Port to use`, then click on the fire icon that says `ESP-IDF: Build, Flash, and Monitor`. This will do everything that has been said, assuming that you've set your board with the `Set Espressif Device Target` button.

<!-- USAGE EXAMPLES -->
## Usage

Here are the commands that you can use:

* `set_nickname` Sets the nickname of a peer
* `get_nickname` Gets the peer's nickname based on their IPv6 address
* `get_ipv6` Gets the peer's IPv6 address bassed on nickname
* `send_message` Sends a message to a peer manually
* `configure_network` Configures **one** of your devices as the leader of the mesh network, though this doesn't really change anything about message sending
* `configure_joiner` Configures **any** device as a joiner, meaning that it joins the mesh created by the device that ran the `configure_network` command
* `turn_on_led` Turns on the onboard LED (must be configured)
* `turn_off_led` Turns off the onboard LED (must be configured)
* `get_lfs_entries` Lists all NVS entries
* `clear_lfs_entries` Clears NVS entries (if any)

You can simply run the command without any arguments e.g `set_nickname` to see if any are needed. With an exception for the LED commands and some LFS commands there will most likely be an argument required for it to run.

<!-- ROADMAP -->
## Roadmap

As of now I would like to implement/am in the progress of implementing:

* [x] Create basic messaging w/ commands
* [x] Create custom method for anyone to advertise their presence to other instances of HomeNet
* [x] Allow the saving of clients like phone contacts
* [x] Allow direct communication with these saved clients like DMs
* [x] Establish a method to ensure the security of the connection
* [ ] Rewrite UDP communication using custom receivers, transmitters, etc
  * [x] Custom transmitter
  * [ ] Custom receiver
* [x] Make documentation simpler for other audiences (may need to reach out)
* [ ] (Maybe) Make an application that communicates with the ESP over BLE to send messages e.g [Meshtastic App(s)](https://meshtastic.org/docs/software/)

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

dj1ch - [tg.1ch0712@gmail.com](tg.1ch0712@gmail.com)

Personal Website - [dj1ch.pages.dev/contact](https://dj1ch.pages.dev/contact)

Project Link: [https://github.com/dj1ch/HomeNet](https://github.com/dj1ch/HomeNet)

<!-- ACKNOWLEDGEMENTS -->
## Acknowledgements

* [Hack Club](https://hackclub.com/)
* [Meshtastic](https://meshtastic.org/)
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
