# EigenRollup

EigenRollup provides a privacy-preserving smart contract on mixed layer 2 Rollup protocols of current main public blockchain, such as Ethereum. EigenRollup initiailly implements the protocol on Arbitrum.

## [WIP] Add New Instructions for private computing

1. Install Dependencies
On Ubuntu, using apt:

First install `curl`, `python3`, and `python3-pip`:
```bash
sudo apt update
sudo apt install -y curl python3 python3-pip
```

Then install Docker Engine:
If any old versions exist, we should uninstall them:
```bash
sudo apt-get remove docker docker-engine docker.io containerd runc
```
It's OK if `apt-get` reports that none of these packages are installed.
After ensure there isn't any old version in the system, we should install Docker Enging using the repository, the insturctuons are:
```bash
# Update the apt package index and install packages to allow apt to use a repository over HTTPS:
sudo apt-get update

sudo apt-get install \
   apt-transport-https \
   ca-certificates \
   curl \
   gnupg \
   lsb-release

# Add Docker’s official GPG key:
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# Use the following command to set up the stable repository:
echo \
  "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Installl Docker Engine
sudo apt-get update

sudo apt-get install docker-ce docker-ce-cli containerd.io
```

Manage Docker as a non-root user:
```bash
# Create the `docker` group
sudo groupadd docker

# Add your user to the `docker` group
sudo udermod -aG docker $USER
newgrp Docker
```

If all the processes success, verify that Docker Engine is installed correctly by running the `hello-world` image:
```bash
docker run hello-world
```


Then we should install Docker Compose (version is 1.29.2):
```bash
# Run this command to download the current stable release of Docker Compose:
sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose

# Apply executable permissions to the binary:
sudo chmod +x /usr/local/bin/docker-compose
```
To test the installation, it will print strings like this:
```console
$ docker-compose --version
docker-compose version 1.29.2, build 5becea4c
```

Finally, we should install `node`, `yarn` and `truffle`:
```bash
touch ~/.bashrc
curl -o- https://raw.githubusercontent.com/creationix/nvm/v0.35.3/install.sh | bash
. ~/.bashrc
nvm install --lts

curl -o- -L https://yarnpkg.com/install.sh | bash
. ~/.bashrc

yarn global add truffle
```


2. To use Arbitrum:

```bash
git clone -b dev https://github.com/ieigen/arbitrum
cd arbitrum

git submodule update --init --recursive

yarn
yarn build
```

3. Running on Local Blockchain

To run Arbitrum locally, you need several things:

  - Launching a Local Ethereum Blockchain (the L1)

  ```bash
  yarn docker:build:geth

  # Set DEVNET_PRIVKEY, for example:
  export DEVNET_PRIVKEY=""
  yarn docker:geth
  ```

  - Configuring your local Arbitrum chain (the L2)

  ```bash
  # If in another terminal, we should set DEVNET_PRIVKEY again with the same value as before

  yarn demo:initialize
  ```

  - Firing up the Arbitrum L2 and Deploying your validator(s)

  ```bash
  yarn demo:deploy
  ```

4. Run tutorial `demo-eigencall`

```bash
cd eigen-tutorials
# Install some dependencies
yarn

# Run tutorial
cd packages/demo-iegencall

yarn run exec
```
