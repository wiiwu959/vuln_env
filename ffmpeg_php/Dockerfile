# FROM php:5.4-apache
FROM amd64/debian:9.11

# RUN apt-get update
# RUN apt-get install git -y
# RUN apt-get install yasm -y 
# RUN apt-get install libsdl1.2-dev -y
# RUN apt-get install libstdl2-devsudo libstdl2-dev -y

# RUN git clone https://git.ffmpeg.org/ffmpeg.git ffmpeg


RUN apt-get update 
RUN apt-get install -y autoconf automake build-essential cmake git-core libass-dev libfreetype6-dev libsdl2-dev libtool libva-dev libvdpau-dev libvorbis-dev libxcb1-dev libxcb-shm0-dev libxcb-xfixes0-dev pkg-config texinfo wget zlib1g-dev
RUN wget -qO- https://www.ffmpeg.org/releases/ffmpeg-2.8.4.tar.gz | tar --strip-components 1 -xz -C /usr/src
RUN cd /usr/src && ./configure --pkg-config-flags="--static" --disable-yasm && make && make install
RUN rm -rf /usr/src/*

RUN set -ex
RUN apt-get update 
RUN apt-get install -y --no-install-recommends php-cli
RUN rm -rf /var/lib/apt/lists/*