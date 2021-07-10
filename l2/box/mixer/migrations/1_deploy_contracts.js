const Mixer = artifacts.require("Mixer");


module.exports = function(deployer) {
    //if (network === "development") return;  // Don't deploy on tests
    deployer.deploy(Mixer, "0xCd27B526f12BfEb656A899C580E8e5f8398e3fFe");
    Mixer.deployed().then( function(newInstance) {
        console.log(newInstance.addreess)
    }
    );
}
