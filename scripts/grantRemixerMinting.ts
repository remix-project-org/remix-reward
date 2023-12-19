import { ethers } from 'ethers'

async function main() {
    try {        
        // proxy on Optimism.
        const address = "0x5d470270e889b61c08C51784cDC73442c4554011"

        // "signer" represents the current selected account and provider.
        const signer = (new ethers.providers.Web3Provider(web3Provider)).getSigner()

        // getContractFactory retruns the compilation result.
        // This will be used in the next line to instantiate an "ethers.Contract" object ot interact with the contract.
        const remixV1 = await ethers.getContractFactory("Remix")
        
        // we finally use the address, the contract interfact and the current context (provider and account)
        // to instantiate an ethers.Contract object.
        let contract = new ethers.Contract(address, remixV1.interface, signer);

        const students = []
               
        const txSafeMint = await contract.grantRemixersMinting(students, 1)
        
        // this wait for the transaction to be mined.
        const result = await txSafeMint.wait()

        console.log(result)
    } catch (e) {
        console.error(e)
    }    
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
    console.error(error)
});

