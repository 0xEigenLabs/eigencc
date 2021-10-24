FROM  ieigen/fns:v1 as fns_builder

COPY $PWD/sgx/ /app/
WORKDIR /app
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup default nightly-2020-10-25
RUN rm -rf /app/release && rm -rf /app/build
RUN mkdir -p build && cd build && cmake .. -DSGX_SIM_MODE=on && make

FROM teaclave/teaclave-build-ubuntu-1804-sgx-2.9.1 as fns_release
COPY --from=fns_builder /app/release/ /app/release/
WORKDIR /app/release/services
EXPOSE 8082
ENTRYPOINT ["/bin/bash", "-c", "source /opt/sgxsdk/environment; ./fns"]
