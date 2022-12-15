"""
Module detecting voting amplification.

"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VotingAmplification(AbstractDetector):
    """
    Detect voting-amplification
    """

    ARGUMENT = (
        "voting-amplification"  # slither will launch the detector with slither.py --mydetector
    )
    HELP = "There are flaws of on-chain governance implementation"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/trailofbits/slither/wiki/Detector-Documentation#voting-amplification"
    WIKI_TITLE = "VOTING_AMPLIFICATION"
    WIKI_DESCRIPTION = "VOTING_AMPLIFICATION"
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract A {
    // ...
    function transferFrom(address from, address to, uint256 value) public returns (bool) {
        _transfer(from, to, value);
        _approve(from, msg.sender, allowance(from, msg.sender).sub(value));
        _moveDelegates(delegates[msg.sender], delegates[to], value); // vulnerable point
        return true;
    }
    // ...
}
```
https://etherscan.io/address/0xa2cd3d43c775978a96bdbf12d733d5a1ed94fb18#code#L533

When defi project just copy&paste code with vulnerability, the above pattern appears.
"""
    WIKI_RECOMMENDATION = "Do not copy&paste code with vulnerabilities."

    def detect_moving_exist(self, contracts):
        result = []
        delegates = "moveDelegate"

        for contract in contracts:
            for func in contract.functions:
                if any(delegates.lower() in callee.name.lower() for callee in func.internal_calls):

                    for node in func.nodes:
                        for _exp in node._internal_calls_as_expressions:
                            exp = str(_exp).lower()
                            if "moveDelegate".lower() in exp:
                                arg = exp[exp.find("(") : -1].split(",")
                                # 1. In calling moveDelegates(), improper position of from and to.
                                # 2. In burn(), moveDelegate(0, to) or moveDelegate(0, from).
                                # 3. In transferFrom(), moveDelegate(msg.sender, to).
                                if len(arg) == 3:
                                    if "to" in arg[0].lower() and "from" in arg[1].lower():
                                        result.append(func)

                                    if "burn" in func.name.lower() and (
                                        "to" in arg[1].lower() or "from" in arg[1].lower()
                                    ):
                                        result.append(func)

                                    if "transferFrom".lower() in func.name.lower():
                                        result.append(func)
        return result

    def _detect(self):

        results = []

        res = self.detect_moving_exist(self.contracts)
        for rep in res:
            info = [
                "voting amplification in ",
                rep,
                "\n",
            ]
            res = self.generate_result(info)
            results.append(res)
        return results
