# Netinstall

The script provides a boot service

Netinstall is designed primarily for networks with an authoritative DHCP server. It sniffs the network for DHCP Request packets and extends the DHCP server's DHCP Offer response to point to its own boot service.

If you are looking for a complete solution that includes its own DHCP server, consider an alternative like [pTFTPD][] or [dnsmasq][].

    python3 -m venv .venv
    . .venv/bin/activate
    python3 -m pip install -r requirements.txt

    sudo python3 netinstall.py \
        --interface en0 \
        --tftp-dir ./tftproot \
        --boot-file netbootxyz.efi

In the above example, we instruct clients to boot from the `[netbootxyz.efi][]` file stored in the directory `tftproot`.

[pTFTPD]: https://github.com/mpetazzoni/ptftpd
[dnsmasq]: http://www.thekelleys.org.uk/dnsmasq/doc.html
[netboot.xyz]: https://netboot.xyz/downloads/


## Creating custom UEFI bootloaders

The [iPXE][] project provides an easy framework for building custom bootloaders. The `ipxe` directory contains an example for building an UEFI bootloader with custom configuration options and a script that executes automatically on boot.

    docker build --tag ipxe_builder .
    docker run --rm -it -v $(pwd):/host ipxe_builder

[iPXE]: https://ipxe.org
