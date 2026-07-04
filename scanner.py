import httpx
from web3 import Web3
from typing import Optional

# ERC20 ABI for basic token functions
ERC20_ABI = [
    {"constant": True, "inputs": [{"name": "_owner", "type": "address"}], "name": "balanceOf", "outputs": [{"name": "balance", "type": "uint256"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "totalSupply", "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "decimals", "outputs": [{"name": "", "type": "uint8"}], "type": "function"},
    {"constant": True, "inputs": [{"name": "_owner", "type": "address"}, {"name": "_spender", "type": "address"}], "name": "allowance", "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "owner", "outputs": [{"name": "", "type": "address"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "symbol", "outputs": [{"name": "", "type": "string"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "name", "outputs": [{"name": "", "type": "string"}], "type": "function"},
]

# Dangerous function selectors
DANGER_SELECTORS = {
    "0x40c10f19": "mint",  # mint(address,uint256)
    "0x8da5cb5b": "owner",  # owner()
    "0x715018a6": "renounceOwnership",  # renounceOwnership()
    "0xf2fde38b": "transferOwnership",  # transferOwnership(address)
    "0xa9059cbb": "transfer",  # transfer(address,uint256)
    "0x23b872dd": "transferFrom",  # transferFrom(address,address,uint256)
    "0x095ea7b3": "approve",  # approve(address,uint256)
}

# Chain RPC endpoints
RPC_ENDPOINTS = {
    1: "https://eth.llamarpc.com",
    8453: "https://mainnet.base.org",
    56: "https://bsc-dataseed.binance.org",
    137: "https://polygon-rpc.com",
    42161: "https://arb1.arbitrum.io/rpc",
    10: "https://mainnet.optimism.io",
}

class TokenScanner:
    def __init__(self):
        self.goplus_api = "https://api.gopluslabs.io/api/v1"
    
    async def scan_token(self, address: str, chain_id: int = 1) -> dict:
        # Validate address
        if not Web3.is_address(address):
            raise ValueError("Invalid Ethereum address")
        
        checksum_address = Web3.to_checksum_address(address)
        
        # Get GoPlus security data
        goplus_data = await self._get_goplus_data(checksum_address, chain_id)
        
        # Get on-chain data
        onchain_data = await self._get_onchain_data(checksum_address, chain_id)
        
        # Analyze and calculate risk score
        analysis = self._analyze_risk(goplus_data, onchain_data)
        
        return {
            "address": checksum_address,
            "chain_id": chain_id,
            **analysis
        }
    
    async def _get_goplus_data(self, address: str, chain_id: int) -> dict:
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(
                    f"{self.goplus_api}/token_security/{chain_id}",
                    params={"contract_addresses": address},
                    timeout=10.0
                )
                data = resp.json()
                if data.get("result"):
                    return data["result"].get(address.lower(), {})
            except Exception as e:
                print(f"GoPlus error: {e}")
        return {}
    
    async def _get_onchain_data(self, address: str, chain_id: int) -> dict:
        rpc_url = RPC_ENDPOINTS.get(chain_id, RPC_ENDPOINTS[1])
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        
        result = {
            "total_supply": 0,
            "owner_balance": 0,
            "owner_address": None,
            "is_contract": False,
            "has_dangerous_functions": False,
        }
        
        try:
            # Check if it's a contract
            code = w3.eth.get_code(Web3.to_checksum_address(address))
            result["is_contract"] = len(code) > 0
            
            if not result["is_contract"]:
                return result
            
            token = w3.eth.contract(address=Web3.to_checksum_address(address), abi=ERC20_ABI)
            
            # Get total supply
            result["total_supply"] = token.functions.totalSupply().call()
            
            # Try to get owner
            try:
                owner = token.functions.owner().call()
                result["owner_address"] = owner
                result["owner_balance"] = token.functions.balanceOf(Web3.to_checksum_address(owner)).call()
            except:
                pass
            
            # Check for dangerous functions in bytecode
            bytecode = code.hex()
            dangerous_sigs = ["40c10f19", "8da5cb5b", "715018a6", "f2fde38b"]
            result["has_dangerous_functions"] = any(sig in bytecode for sig in dangerous_sigs)
            
        except Exception as e:
            print(f"Onchain error: {e}")
        
        return result
    
    def _analyze_risk(self, goplus: dict, onchain: dict) -> dict:
        risk_score = 0
        findings = []
        
        # GoPlus checks
        if goplus.get("is_honeypot") == "1":
            risk_score += 40
            findings.append("🚨 HONEYPOT DETECTED - Cannot sell tokens")
        
        if goplus.get("is_mintable") == "1":
            risk_score += 20
            findings.append("⚠️ Token is mintable - supply can be increased")
        
        if goplus.get("is_proxy") == "1":
            risk_score += 15
            findings.append("⚠️ Proxy contract - can be upgraded/malicious")
        
        if goplus.get("owner_change_balance") == "1":
            risk_score += 25
            findings.append("🚨 Owner can change balances")
        
        if goplus.get("can_take_back_ownership") == "1":
            risk_score += 20
            findings.append("⚠️ Owner can take back ownership")
        
        if goplus.get("is_blacklisted") == "1":
            risk_score += 10
            findings.append("⚠️ Token has blacklist function")
        
        if goplus.get("is_whitelisted") == "1":
            risk_score += 5
            findings.append("ℹ️ Token has whitelist function")
        
        if goplus.get("transfer_cooldown") == "1":
            risk_score += 10
            findings.append("⚠️ Transfer cooldown enabled")
        
        # Holder concentration
        holder_pct = float(goplus.get("top_10_holder_rate", "0") or "0")
        if holder_pct > 0.5:
            risk_score += 15
            findings.append(f"⚠️ Top 10 holders own {holder_pct*100:.1f}%")
        
        owner_pct = float(goplus.get("owner_rate", "0") or "0")
        if owner_pct > 0.1:
            risk_score += 15
            findings.append(f"⚠️ Owner holds {owner_pct*100:.1f}%")
        
        # LP checks
        lp_locked = goplus.get("is_lp_locked") == "1"
        if not lp_locked:
            risk_score += 10
            findings.append("⚠️ Liquidity not locked")
        
        # Onchain checks
        if onchain.get("has_dangerous_functions"):
            risk_score += 10
            findings.append("⚠️ Contract has dangerous functions (mint, ownership)")
        
        # Cap risk score
        risk_score = min(risk_score, 100)
        
        # Determine risk level
        if risk_score < 20:
            risk_level = "Safe"
            recommendation = "Low risk detected. Always DYOR before investing."
        elif risk_score < 50:
            risk_level = "Caution"
            recommendation = "Some risk factors found. Proceed with caution."
        elif risk_score < 80:
            risk_level = "Danger"
            recommendation = "High risk detected. Multiple red flags found."
        else:
            risk_level = "Scam"
            recommendation = "SCAM DETECTED. Do not interact with this token."
        
        if not findings:
            findings.append("✅ No major issues detected")
        
        # Get token name/symbol from GoPlus or onchain
        token_name = goplus.get("token_name", "Unknown Token")
        token_symbol = goplus.get("token_symbol", "")

        has_blacklist = goplus.get("is_blacklisted") == "1"
        has_max_tx = goplus.get("is_max_tx_amount_enable") == "1"

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "token_name": token_name,
            "token_symbol": token_symbol,
            "is_honeypot": goplus.get("is_honeypot") == "1",
            "is_mintable": goplus.get("is_mintable") == "1",
            "is_proxy": goplus.get("is_proxy") == "1",
            "owner_can_change_balance": goplus.get("owner_change_balance") == "1",
            "lp_locked": lp_locked,
            "has_blacklist": has_blacklist,
            "has_max_tx": has_max_tx,
            "top_holder_pct": holder_pct,
            "owner_pct": owner_pct,
            "findings": findings,
            "recommendation": recommendation,
        }
