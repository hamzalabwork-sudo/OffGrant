# PureChain node (geth 1.13.15 fork, Clique PoA, Cancun, zero gas) from the official v1.0.1 release binary,
# verified against the release SHA256SUMS (testbed/purechain/bin). tc is included so a node can impose
# netem faults on its own interfaces (needs --cap-add NET_ADMIN).
FROM alpine:3.20
# apk verifies package signatures; http avoids the TLS interception on this host's network.
RUN sed -i 's/https/http/' /etc/apk/repositories && apk add --no-cache iproute2-tc socat
COPY bin/purechain-geth-v1.0.1-linux-amd64 /usr/local/bin/geth
RUN chmod +x /usr/local/bin/geth && geth version | head -3
ENTRYPOINT ["geth"]
