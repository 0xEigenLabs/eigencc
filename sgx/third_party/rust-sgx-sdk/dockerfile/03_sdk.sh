if [ $SDK_DIST != "SELF_BUILT" ]; then
    cd /root && \
    curl -o sdk.sh $SDK_URL && \
    chmod a+x /root/sdk.sh && \
    echo -e 'no\n/opt' | ./sdk.sh && \
    echo 'source /opt/sgxsdk/environment' >> /root/.bashrc && \
    cd /root && \
    rm ./sdk.sh
else
    cd /root && \
    git clone --recursive https://github.com/intel/linux-sgx && \
    cd linux-sgx && \
    git checkout 608fe1df4c7c99433b0b8e9abdd31ba67c79ceb0 && \
    ./download_prebuilt.sh && \
    make -j "$(nproc)" sdk_install_pkg && \
    echo -e 'no\n/opt' | ./linux/installer/bin/sgx_linux_x64_sdk_2.12.100.3.bin && \
    echo 'source /opt/sgxsdk/environment' >> /root/.bashrc && \
    cd /root && \
    rm -rf /root/linux-sgx
fi
