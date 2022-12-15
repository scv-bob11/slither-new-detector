"""
Module detecting improper use of ecrecover.

"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import Binary, BinaryType
from slither.slithir.operations.solidity_call import SolidityCall
from slither.slithir.variables.constant import Constant


class Verification(AbstractDetector):
    """
    Detect improper use of ecrecover
    """

    ARGUMENT = "ecrecover"  # slither will launch the detector with slither.py --mydetector
    HELP = "Return value of ecrecover is not checked. Signature does not contain a nonce."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW

    WIKI = " "
    WIKI_TITLE = "ECRECOVER"
    WIKI_DESCRIPTION = "ECRECOVER"
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract A {
    function verify(
        address signer, 
        bytes32 sigV, 
        bytes32 sigR, 
        bytes8 sigS
    ) public view returns (bool) {
        bytes data = abi.encode(signer); // vulnerable point
        address recovered = ecrecover(data, sigV, sigR, sigS); 
        return signer == recovered;
    }

    function transferWithSig(
        bytes calldata sig,
        uint256 amount,
        bytes32 data,
        uint256 expiration,
        address to
    ) external returns (address from) {
        require(amount > 0);
        require(
            expiration == 0 || block.number <= expiration,
            "Signature is expired"
        );

        bytes32 dataHash = hashEIP712MessageWithAddress(
            hashTokenTransferOrder(msg.sender, amount, data, expiration),
            address(this)
        );

        require(disabledHashes[dataHash] == false, "Sig deactivated");
        disabledHashes[dataHash] = true;

        from = ecrecovery(dataHash, sig); // vulnerable point
        _transferFrom(from, address(uint160(to)), amount);
    }
}
```
First, signature does not contain nonce.   
Second, there is no verification of ecrecover's return value.   
"""
    WIKI_RECOMMENDATION = "Check return value of ecrecover and signature contains a nonce"

    def _detect(self):

        results = []

        for contract in self.compilation_unit.contracts:
            # ecrecover를 사용하는 함수를 찾자
            for function in contract.functions:
                for call in function.solidity_calls:
                    if call.name == "ecrecover(bytes32,uint8,bytes32,bytes32)":
                        flag = 0
                        for vari in function._variables:
                            if "nonce" in vari.lower():
                                flag = 1
                        if flag == 0:
                            info = [
                                "no nonce in ",
                                function,
                                "\n",
                            ]
                            res = self.generate_result(info)
                            results.append(res)
                        flag = 0

                        find_erecovery = 0
                        for node in function.nodes:

                            for ir in node.irs:
                                if find_erecovery == 1:
                                    if isinstance(ir, Binary):
                                        if (ir.type == BinaryType.NOT_EQUAL) or (
                                            ir.type == BinaryType.EQUAL
                                        ):
                                            flag = 1
                                else:
                                    if (
                                        isinstance(ir, SolidityCall)
                                        and ir.function.name
                                        == "ecrecover(bytes32,uint8,bytes32,bytes32)"
                                    ):
                                        find_erecovery = 1
                        if flag == 0:
                            info = [
                                "no check erecovery return in ",
                                function,
                                "\n",
                            ]
                            res = self.generate_result(info)
                            results.append(res)
        return results
