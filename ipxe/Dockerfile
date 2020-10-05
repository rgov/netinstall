FROM ubuntu:bionic

RUN apt-get update && apt-get install -y \
        build-essential \
        git
    
RUN git clone http://git.ipxe.org/ipxe.git \
    && cd ipxe \
    && git checkout tags/v1.20.1

WORKDIR /ipxe/src

VOLUME /host

CMD cp -r /host/config/*.h ./config/local/ \
    && make bin-x86_64-efi/ipxe.efi \
        EMBED=/host/script.ipxe \
    && cp bin-x86_64-efi/ipxe.efi /host/
