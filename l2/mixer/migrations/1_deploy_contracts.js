require('dotenv').config()
const Mixer = artifacts.require("Mixer")

module.exports = function(deployer) {
    //if (network === "development") return;  // Don't deploy on tests
  deployer.deploy(Mixer, process.env.MIMC_ADDR);
  Mixer.deployed().then(function(instance) {
    console.log(instance.addreess)
  }
  );
}
