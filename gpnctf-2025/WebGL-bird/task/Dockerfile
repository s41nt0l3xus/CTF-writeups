FROM debian:12 AS build

RUN apt-get update && apt-get install -y \
    autoconf \
    autoconf-archive \
    automake \
    build-essential \
    ccache \
    clang-19 \
    cmake \
    curl \
    fonts-liberation2 \
    git \
    libfontconfig1-dev \
    libgl1-mesa-dev \
    libgl1-mesa-dri \
    libgl1-mesa-glx \
    libpulse-dev \
    libssl-dev \
    libx11-dev \
    libxext-dev \
    libxinerama-dev \
    libxnvctrl-dev \
    libxrandr-dev \
    libxcb1-dev \
    libxcursor-dev \
    libxi-dev \
    mesa-common-dev \
    mesa-utils \
    nasm \
    ninja-build \
    pkg-config \
    python3 \
    python3-pip \
    python3-ply \
    qt6-base-dev \
    qt6-tools-dev-tools \
    qt6-wayland \
    tar \
    unzip \
    xvfb \
    zip \
    && apt-get clean

RUN useradd -m ctf
USER ctf
WORKDIR /work/ladybird

RUN git clone https://github.com/LadybirdBrowser/ladybird.git /work/ladybird && \
git checkout 223b13ae936d72fe379e2642efd683c1620b547c

ADD patches /work/patches
RUN git apply /work/patches/*.patch

RUN ./Meta/ladybird.sh vcpkg \
&& CC=clang-19 CXX=clang++-19 cmake --preset Distribution -DCMAKE_BUILD_TYPE=RelWithDebInfo \
&& ninja -C Build/distribution ladybird

FROM debian:12 AS flag-reader
RUN apt-get update && apt-get install -y gcc \
&& apt-get clean
COPY read_flag.c .
RUN gcc -o /read_flag read_flag.c

FROM debian:12
RUN apt-get update && apt-get install -y gcc \
libgl1-mesa-dri \
libgl1-mesa-glx \
mesa-utils \
xvfb \
socat \
python3 \
libqt6core6 \
libqt6gui6 \
libqt6widgets6 \
libqt6network6 \
libopengl0 \
libpulse0 \
libxi6 \
libvulkan1 \
libatomic1 \
libcrypt1 \
libbsd0 \
libmd0 \
libxnvctrl0 \
qt6-qpa-plugins \
&& apt-get clean

WORKDIR /work/ladybird
ARG FLAG=GPNCTF{fake_flag}
RUN echo "$FLAG" > flag.txt
COPY --from=flag-reader /read_flag .
RUN chmod u+s read_flag && \
chmod 700 flag.txt

RUN useradd -m ctf
USER ctf

ENV XDG_RUNTIME_DIR=/home/ctf/.xdg-runtime
ENV DISPLAY=:99

COPY --from=build /work/ladybird/Build/distribution/bin/Ladybird bin/
COPY --from=build /work/ladybird/Build/distribution/libexec/RequestServer libexec/
COPY --from=build /work/ladybird/Build/distribution/libexec/WebContent libexec/
COPY --from=build /work/ladybird/Build/distribution/libexec/ImageDecoder libexec/
COPY --from=build /work/ladybird/Build/distribution/share/ share/

COPY --chmod=555 run.sh run.sh
COPY --chmod=555 socat.sh socat.sh
COPY --chmod=555 server.py server.py

ENTRYPOINT ["sh", "-c", "Xvfb :99 -screen 0 1280x720x24 & ./socat.sh" ]
