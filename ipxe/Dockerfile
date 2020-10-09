FROM alpine:3.12

RUN apk add gcc g++ git make perl

RUN git clone http://git.ipxe.org/ipxe.git \
    && cd ipxe \
    && git checkout tags/v1.20.1

WORKDIR /ipxe/src

VOLUME /host

CMD cp -r /host/config/*.h ./config/local/ \
    && make -j`nproc` bin-x86_64-efi/ipxe.efi \
        EMBED=/host/default.ipxe \
    && cp bin-x86_64-efi/ipxe.efi /host/
