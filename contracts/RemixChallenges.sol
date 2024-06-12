// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";

import "./Proof.sol";

contract RemixChallenges is Initializable, AccessControlUpgradeable, UUPSUpgradeable {
    
    struct Challenge {
        uint256 set;
        uint256 publishersCount;
        address verifier;
        uint256 challengeHash;
        uint256 max; 
        string tokenType; 
        string payload; 
        bytes hash;
    }
    uint256 public challengeIndex;
    mapping  (uint256 => Challenge) public challenges;

    mapping (bytes => uint) public nullifiers;
    mapping (bytes => uint) public publishers;

    address public rewardContract;
    
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {}

    function initialize() initializer public {
        __AccessControl_init();
        __UUPSUpgradeable_init();
        
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /** 
      * @notice This function sets the address of the reward contract.
      * @dev Only the default admin can call this function.
      * @param _reward The address of the reward contract.
      */
    function setRewardContract (address _reward) public onlyRole(DEFAULT_ADMIN_ROLE) {
        rewardContract = _reward;
    }

    /** 
      * @notice This function sets a challenge with a given struct Challenge in storage.
      * @dev Only the default admin can call this function.
      * @param challenge The struct Challenge that contains all necessary data for a challenge.
      */
    function setChallenge(Challenge calldata challenge) public onlyRole(DEFAULT_ADMIN_ROLE)  {
        challenges[challengeIndex] = challenge;
        challenges[challengeIndex].publishersCount = 0;
        challenges[challengeIndex].set = 1;
        challengeIndex++;
    }

    /** 
      * @notice This function is used by publishers to publish their proofs for a given challenge.
      * @param index The index of the challenge in the challenges mapping.
      * @param proof The struct Proof containing all necessary data for a proof. This includes values a, b, c and d.
      * @param input The array of 3 uints containing additional input data for a challenge. This includes a challengeHash, a random number (r) and a nullifier (s).
      */
    function publishChallenge (uint256 index, ZKVerifier.Proof memory proof, uint[3] memory input) public {
        require(rewardContract != address(0), "reward contract not set");
        Challenge storage challenge = challenges[index];
        require(challenge.set == 1, "challenge not set");
        require(challenge.verifier != address(0), "no challenge started");
        require(challenge.publishersCount < challenge.max, "publishers reached maximum amount");
        bytes memory nullifier = abi.encodePacked(index, input[2]);
        bytes memory publisher = abi.encodePacked(index, msg.sender);
        require(nullifiers[nullifier] == 0, "proof already published");
        require(publishers[publisher] == 0, "current publisher has already submitted");
        require(challenge.challengeHash == input[1], "provided challenge is not valid");
        
        // function verifyTx(Proof memory proof, uint[3] memory input) public view returns (bool r)
        (bool success, bytes memory data) = challenge.verifier.call{ value: 0 }(
            abi.encodeWithSignature("verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[3])", proof.a, proof.b, proof.c, input)
        );
        
        require(success, "the call to the verifier failed");

        (bool verified) = abi.decode(data, (bool));        
        require(verified, "the provided proof is not valid");        
        
        challenge.publishersCount++;

        nullifiers[nullifier] = 1;
        publishers[publisher] = 1;

        // function safeMint(address to, string memory tokenType, string memory payload, bytes memory hash, uint256 mintGrant) public onlyRole(DEFAULT_ADMIN_ROLE)
        (bool successMint, bytes memory dataMint) = rewardContract.call{ value: 0 }(
            abi.encodeWithSignature("safeMint(address,string,string,bytes,uint256)", 
                msg.sender, 
                challenge.tokenType,
                challenge.payload,
                challenge.hash,
                1
            )
        );

        if (!successMint) {
            if (dataMint.length == 0) revert();
            assembly {
                revert(add(32, dataMint), mload(dataMint))
            }
        }
    }

    function _authorizeUpgrade(address newImplementation) internal override   {

    }

    function version () public pure returns (string memory) {
        return "1.0.0";
    }
}