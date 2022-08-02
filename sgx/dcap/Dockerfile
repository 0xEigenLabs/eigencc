FROM ubuntu:18.04

ENV DCAP_VERSION 1.9.100.3-bionic1
ENV VERSION 2.12.100.3-bionic1
ENV SGX_DOWNLOAD_URL_BASE "https://download.01.org/intel-sgx/sgx-dcap/1.9/linux/distro/ubuntu18.04-server/"
ENV SGX_LINUX_X64_SDK sgx_linux_x64_sdk_2.12.100.3.bin
ENV SGX_LINUX_X64_SDK_URL "$SGX_DOWNLOAD_URL_BASE/$SGX_LINUX_X64_SDK"

ENV DEBIAN_FRONTEND=noninteractive

ENV RUST_TOOLCHAIN nightly-2020-10-25

# install SGX dependencies
RUN apt-get update && apt-get install -q -y \
    build-essential \
    ocaml \
    ocamlbuild \
    automake \
    autoconf \
    libtool \
    wget \
    python \
    python3 \
    libssl-dev \
    libcurl4-openssl-dev \
    libprotobuf-dev \
    curl \
    pkg-config

RUN curl -sL https://deb.nodesource.com/setup_12.x | bash -
RUN apt-get install nodejs -y

RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | \
    tee /etc/apt/sources.list.d/intel-sgx.list
RUN curl -fsSL  https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
RUN apt-get update && apt-get install -y \
    libsgx-dcap-ql=$DCAP_VERSION \
    libsgx-dcap-default-qpl=$DCAP_VERSION \
    libsgx-dcap-ql-dbgsym=$DCAP_VERSION \
    libsgx-dcap-default-qpl-dbgsym=$DCAP_VERSION \
    libsgx-urts=$VERSION \
    libsgx-enclave-common=$VERSION \
    libsgx-enclave-common-dev=$VERSION \
    libsgx-enclave-common-dbgsym=$VERSION \
    libsgx-quote-ex=$VERSION \
    libsgx-quote-ex-dev=$VERSION \
    libsgx-dcap-ql-dev=$DCAP_VERSION \
    libsgx-dcap-default-qpl-dev=$DCAP_VERSION \
    libsgx-qe3-logic=$DCAP_VERSION \
    libsgx-pce-logic=$DCAP_VERSION \
    libsgx-headers=$VERSION \
    sgx-aesm-service=$VERSION \
    libsgx-ae-pce=$VERSION \
    libsgx-ae-le=$VERSION \
    libsgx-ae-qe3=$DCAP_VERSION \
    libsgx-ae-qve=$DCAP_VERSION \
    libsgx-launch=$VERSION \
    libsgx-aesm-launch-plugin=$VERSION \
    libsgx-epid=$VERSION

RUN mkdir /var/run/aesmd && mkdir /etc/init
RUN wget $SGX_LINUX_X64_SDK_URL               && \
    chmod u+x $SGX_LINUX_X64_SDK              && \
    echo -e 'no\n/opt' | ./$SGX_LINUX_X64_SDK && \
    rm $SGX_LINUX_X64_SDK                     && \
    echo 'source /opt/sgxsdk/environment' >> ~/.bashrc

# install Rust and its dependencies

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y   && \
    . $HOME/.cargo/env                                                        && \
    rustup default $RUST_TOOLCHAIN                                            && \
    rustup component add rust-src rls rust-analysis clippy rustfmt            && \
    echo 'source $HOME/.cargo/env' >> ~/.bashrc                               && \
    rm -rf /root/.cargo/registry && rm -rf /root/.cargo/git

# install other dependencies for building

RUN apt-get update && apt-get install -q -y \
    software-properties-common \
    cmake \
    pypy \
    pypy-dev

RUN add-apt-repository ppa:git-core/ppa && \
  apt-get update && apt-get install -q -y git

# install dependencies for testing and coverage

RUN apt-get update && apt-get install -q -y \
    lsof \
    procps \
    lcov \
    llvm \
    curl \
    iproute2 \
    python3-pip

RUN pip3 install pyopenssl toml cryptography yapf requests Pillow

# enable oen way access
RUN sed -i 's/USE_SECURE_CERT=TRUE/USE_SECURE_CERT=FALSE/g' /etc/sgx_default_qcnl.conf

# clean up apt caches

RUN apt-get clean && \
    rm -fr /var/lib/apt/lists/* /tmp/* /var/tmp/*
