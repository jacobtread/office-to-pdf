# Slightly modified verison of https://github.com/unoconv/unoserver-docker/blob/main/README.adoc

FROM --platform=$BUILDPLATFORM eclipse-temurin:22.0.2_9-jdk-alpine

ARG UID=worker
ARG GID=worker
ARG VERSION_UNOSERVER=2.2.1

LABEL org.opencontainers.image.title="unoserver-docker"
LABEL org.opencontainers.image.description="Container image that contains unoserver and LibreOffice including large set of fonts for file format conversions"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.documentation="https://github.com/unoconv/unoserver-docker/blob/main/README.adoc"
LABEL org.opencontainers.image.source="https://github.com/unoconv/unoserver-docker"
LABEL org.opencontainers.image.url="https://github.com/unoconv/unoserver-docker"

WORKDIR /

RUN addgroup -S ${GID} && adduser -S ${UID} -G ${GID}

RUN apk add --no-cache \
    bash curl \
    py3-pip \
    libreoffice \
    supervisor

# fonts - https://wiki.alpinelinux.org/wiki/Fonts
RUN apk add --no-cache \
    font-noto font-noto-cjk font-noto-extra \
    terminus-font \
    ttf-font-awesome \
    ttf-dejavu \
    ttf-freefont \
    ttf-hack \
    ttf-inconsolata \
    ttf-liberation \
    ttf-mononoki  \
    ttf-opensans   \
    fontconfig && \
    fc-cache -f

RUN rm -rf /var/cache/apk/* /tmp/*

# https://github.com/unoconv/unoserver/
RUN pip install --break-system-packages -U unoserver==${VERSION_UNOSERVER}

USER ${UID}
WORKDIR /home/worker
ENV HOME="/home/worker"

VOLUME ["/data"]
EXPOSE 2003
ENTRYPOINT ["unoserver", "--interface", "0.0.0.0"]
