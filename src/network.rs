//! Network definitions and known token deployments.
//!
//! This module defines supported networks and their chain IDs,
//! and provides statically known USDC deployments per network.
//!
//! # CAIP-2 Support
//!
//! Each network can be converted to/from a CAIP-2 chain identifier using
//! [`Network::to_chain_id()`] and [`TryFrom<ChainId>`].

use crate::chain::ChainId;
use crate::types::{MixedAddress, TokenAsset, TokenDeployment, TokenDeploymentEip712};
use alloy::primitives::address;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use std::borrow::Borrow;
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::str::FromStr;

/// Supported blockchain networks.
///
/// Used to differentiate between testnet and mainnet environments for the x402 protocol.
/// Each network has an associated CAIP-2 chain identifier accessible via [`Network::to_chain_id()`].
#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Network {
    // === EVM Networks ===
    /// Base Sepolia testnet (chain ID 84532).
    #[serde(rename = "base-sepolia")]
    BaseSepolia,
    /// Base mainnet (chain ID 8453).
    #[serde(rename = "base")]
    Base,
    /// XDC mainnet (chain ID 50).
    #[serde(rename = "xdc")]
    XdcMainnet,
    /// Avalanche Fuji testnet (chain ID 43113)
    #[serde(rename = "avalanche-fuji")]
    AvalancheFuji,
    /// Avalanche Mainnet (chain ID 43114)
    #[serde(rename = "avalanche")]
    Avalanche,
    /// Polygon Amoy testnet (chain ID 80002).
    #[serde(rename = "polygon-amoy")]
    PolygonAmoy,
    /// Polygon mainnet (chain ID 137).
    #[serde(rename = "polygon")]
    Polygon,
    /// Sei mainnet (chain ID 1329).
    #[serde(rename = "sei")]
    Sei,
    /// Sei testnet (chain ID 1328).
    #[serde(rename = "sei-testnet")]
    SeiTestnet,
    /// BSC testnet (chain ID 97).
    #[serde(rename = "bsc-testnet")]
    BscTestnet,
    /// BSC mainnet (chain ID 56).
    #[serde(rename = "bsc")]
    Bsc,
    /// XRPL EVM Sidechain mainnet (chain ID 1440000).
    #[serde(rename = "xrpl-evm")]
    XrplEvm,
    /// Peaq mainnet (chain ID 3338).
    #[serde(rename = "peaq")]
    Peaq,
    /// IoTeX mainnet (chain ID 4689).
    #[serde(rename = "iotex")]
    IoTeX,
    /// Celo mainnet (chain ID 42220).
    #[serde(rename = "celo")]
    Celo,
    /// Celo Alfajores testnet (chain ID 44787).
    #[serde(rename = "celo-alfajores")]
    CeloAlfajores,

    // === Solana Networks ===
    /// Solana Mainnet - Live production environment for deployed applications
    #[serde(rename = "solana")]
    Solana,
    /// Solana Devnet - Testing with public accessibility for developers experimenting with their applications
    #[serde(rename = "solana-devnet")]
    SolanaDevnet,

    // === Aptos Networks ===
    /// Aptos Mainnet
    #[serde(rename = "aptos")]
    Aptos,
    /// Aptos Testnet
    #[serde(rename = "aptos-testnet")]
    AptosTestnet,
}

impl Display for Network {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::BaseSepolia => write!(f, "base-sepolia"),
            Network::Base => write!(f, "base"),
            Network::XdcMainnet => write!(f, "xdc"),
            Network::AvalancheFuji => write!(f, "avalanche-fuji"),
            Network::Avalanche => write!(f, "avalanche"),
            Network::Solana => write!(f, "solana"),
            Network::SolanaDevnet => write!(f, "solana-devnet"),
            Network::PolygonAmoy => write!(f, "polygon-amoy"),
            Network::Polygon => write!(f, "polygon"),
            Network::Sei => write!(f, "sei"),
            Network::SeiTestnet => write!(f, "sei-testnet"),
            Network::BscTestnet => write!(f, "bsc-testnet"),
            Network::Bsc => write!(f, "bsc"),
            Network::XrplEvm => write!(f, "xrpl-evm"),
            Network::Peaq => write!(f, "peaq"),
            Network::IoTeX => write!(f, "iotex"),
            Network::Celo => write!(f, "celo"),
            Network::CeloAlfajores => write!(f, "celo-alfajores"),
            Network::Aptos => write!(f, "aptos"),
            Network::AptosTestnet => write!(f, "aptos-testnet"),
        }
    }
}

/// The blockchain family/ecosystem a network belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkFamily {
    /// EVM-compatible chains (Ethereum, Base, Polygon, etc.)
    Evm,
    /// Solana blockchain
    Solana,
    /// Aptos blockchain (Move-based)
    Aptos,
}

impl From<Network> for NetworkFamily {
    fn from(value: Network) -> Self {
        match value {
            Network::BaseSepolia => NetworkFamily::Evm,
            Network::Base => NetworkFamily::Evm,
            Network::XdcMainnet => NetworkFamily::Evm,
            Network::AvalancheFuji => NetworkFamily::Evm,
            Network::Avalanche => NetworkFamily::Evm,
            Network::Solana => NetworkFamily::Solana,
            Network::SolanaDevnet => NetworkFamily::Solana,
            Network::PolygonAmoy => NetworkFamily::Evm,
            Network::Polygon => NetworkFamily::Evm,
            Network::Sei => NetworkFamily::Evm,
            Network::SeiTestnet => NetworkFamily::Evm,
            Network::BscTestnet => NetworkFamily::Evm,
            Network::Bsc => NetworkFamily::Evm,
            Network::XrplEvm => NetworkFamily::Evm,
            Network::Peaq => NetworkFamily::Evm,
            Network::IoTeX => NetworkFamily::Evm,
            Network::Celo => NetworkFamily::Evm,
            Network::CeloAlfajores => NetworkFamily::Evm,
            Network::Aptos => NetworkFamily::Aptos,
            Network::AptosTestnet => NetworkFamily::Aptos,
        }
    }
}

impl Network {
    /// Return all known [`Network`] variants.
    pub fn variants() -> &'static [Network] {
        &[
            // EVM networks
            Network::BaseSepolia,
            Network::Base,
            Network::XdcMainnet,
            Network::AvalancheFuji,
            Network::Avalanche,
            Network::PolygonAmoy,
            Network::Polygon,
            Network::Sei,
            Network::SeiTestnet,
            Network::BscTestnet,
            Network::Bsc,
            Network::XrplEvm,
            Network::Peaq,
            Network::IoTeX,
            Network::Celo,
            Network::CeloAlfajores,
            // Solana networks
            Network::Solana,
            Network::SolanaDevnet,
            // Aptos networks
            Network::Aptos,
            Network::AptosTestnet,
        ]
    }

    /// Returns the EVM chain ID for this network, if applicable.
    ///
    /// Returns `None` for non-EVM networks (Solana, Aptos).
    pub fn evm_chain_id(&self) -> Option<u64> {
        match self {
            Network::BaseSepolia => Some(84532),
            Network::Base => Some(8453),
            Network::XdcMainnet => Some(50),
            Network::AvalancheFuji => Some(43113),
            Network::Avalanche => Some(43114),
            Network::PolygonAmoy => Some(80002),
            Network::Polygon => Some(137),
            Network::Sei => Some(1329),
            Network::SeiTestnet => Some(1328),
            Network::BscTestnet => Some(97),
            Network::Bsc => Some(56),
            Network::XrplEvm => Some(1440000),
            Network::Peaq => Some(3338),
            Network::IoTeX => Some(4689),
            Network::Celo => Some(42220),
            Network::CeloAlfajores => Some(44787),
            // Non-EVM networks
            Network::Solana | Network::SolanaDevnet | Network::Aptos | Network::AptosTestnet => {
                None
            }
        }
    }

    /// Converts this network to a CAIP-2 chain identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// use infra402_facilitator::network::Network;
    ///
    /// let chain_id = Network::Base.to_chain_id();
    /// assert_eq!(chain_id.to_string(), "eip155:8453");
    ///
    /// let solana_id = Network::Solana.to_chain_id();
    /// assert_eq!(solana_id.to_string(), "solana:mainnet");
    /// ```
    pub fn to_chain_id(&self) -> ChainId {
        match self {
            // EVM networks use eip155:{chainId}
            Network::BaseSepolia => ChainId::eip155(84532),
            Network::Base => ChainId::eip155(8453),
            Network::XdcMainnet => ChainId::eip155(50),
            Network::AvalancheFuji => ChainId::eip155(43113),
            Network::Avalanche => ChainId::eip155(43114),
            Network::PolygonAmoy => ChainId::eip155(80002),
            Network::Polygon => ChainId::eip155(137),
            Network::Sei => ChainId::eip155(1329),
            Network::SeiTestnet => ChainId::eip155(1328),
            Network::BscTestnet => ChainId::eip155(97),
            Network::Bsc => ChainId::eip155(56),
            Network::XrplEvm => ChainId::eip155(1440000),
            Network::Peaq => ChainId::eip155(3338),
            Network::IoTeX => ChainId::eip155(4689),
            Network::Celo => ChainId::eip155(42220),
            Network::CeloAlfajores => ChainId::eip155(44787),
            // Solana networks
            Network::Solana => ChainId::solana_mainnet(),
            Network::SolanaDevnet => ChainId::solana_devnet(),
            // Aptos networks
            Network::Aptos => ChainId::aptos_mainnet(),
            Network::AptosTestnet => ChainId::aptos_testnet(),
        }
    }

    /// Returns the network family for this network.
    pub fn family(&self) -> NetworkFamily {
        NetworkFamily::from(*self)
    }

    /// Returns true if this is a testnet.
    pub fn is_testnet(&self) -> bool {
        matches!(
            self,
            Network::BaseSepolia
                | Network::AvalancheFuji
                | Network::PolygonAmoy
                | Network::SeiTestnet
                | Network::BscTestnet
                | Network::CeloAlfajores
                | Network::SolanaDevnet
                | Network::AptosTestnet
        )
    }

    /// Attempts to create a Network from an EVM chain ID.
    pub fn from_evm_chain_id(chain_id: u64) -> Option<Self> {
        match chain_id {
            84532 => Some(Network::BaseSepolia),
            8453 => Some(Network::Base),
            50 => Some(Network::XdcMainnet),
            43113 => Some(Network::AvalancheFuji),
            43114 => Some(Network::Avalanche),
            80002 => Some(Network::PolygonAmoy),
            137 => Some(Network::Polygon),
            1329 => Some(Network::Sei),
            1328 => Some(Network::SeiTestnet),
            97 => Some(Network::BscTestnet),
            56 => Some(Network::Bsc),
            1440000 => Some(Network::XrplEvm),
            3338 => Some(Network::Peaq),
            4689 => Some(Network::IoTeX),
            42220 => Some(Network::Celo),
            44787 => Some(Network::CeloAlfajores),
            _ => None,
        }
    }
}

/// Error when converting from a ChainId to Network.
#[derive(Debug, Clone, thiserror::Error)]
#[error("unknown chain ID: {0}")]
pub struct UnknownChainIdError(pub ChainId);

impl TryFrom<&ChainId> for Network {
    type Error = UnknownChainIdError;

    fn try_from(chain_id: &ChainId) -> Result<Self, Self::Error> {
        // Handle EVM chains
        if chain_id.is_evm() {
            if let Some(evm_id) = chain_id.evm_chain_id() {
                if let Some(network) = Network::from_evm_chain_id(evm_id) {
                    return Ok(network);
                }
            }
        }

        // Handle Solana chains
        if chain_id.is_solana() {
            return match chain_id.reference.as_str() {
                "mainnet" => Ok(Network::Solana),
                "devnet" => Ok(Network::SolanaDevnet),
                _ => Err(UnknownChainIdError(chain_id.clone())),
            };
        }

        // Handle Aptos chains
        if chain_id.is_aptos() {
            return match chain_id.reference.as_str() {
                "mainnet" => Ok(Network::Aptos),
                "testnet" => Ok(Network::AptosTestnet),
                _ => Err(UnknownChainIdError(chain_id.clone())),
            };
        }

        Err(UnknownChainIdError(chain_id.clone()))
    }
}

impl TryFrom<ChainId> for Network {
    type Error = UnknownChainIdError;

    fn try_from(chain_id: ChainId) -> Result<Self, Self::Error> {
        Network::try_from(&chain_id)
    }
}

impl From<&Network> for ChainId {
    fn from(network: &Network) -> Self {
        network.to_chain_id()
    }
}

impl From<Network> for ChainId {
    fn from(network: Network) -> Self {
        network.to_chain_id()
    }
}

/// Lazily initialized known USDC deployment on Base Sepolia as [`USDCDeployment`].
static USDC_BASE_SEPOLIA: Lazy<USDCDeployment> = Lazy::new(|| {
    USDCDeployment(TokenDeployment {
        asset: TokenAsset {
            address: address!("0x036CbD53842c5426634e7929541eC2318f3dCF7e").into(),
            network: Network::BaseSepolia,
        },
        decimals: 6,
        eip712: Some(TokenDeploymentEip712 {
            name: "USDC".into(),
            version: "2".into(),
        }),
    })
});

/// Lazily initialized known USDC deployment on Base mainnet as [`USDCDeployment`].
static USDC_BASE: Lazy<USDCDeployment> = Lazy::new(|| {
    USDCDeployment(TokenDeployment {
        asset: TokenAsset {
            address: address!("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913").into(),
            network: Network::Base,
        },
        decimals: 6,
        eip712: Some(TokenDeploymentEip712 {
            name: "USD Coin".into(),
            version: "2".into(),
        }),
    })
});

/// Lazily initialized known USDC deployment on XDC mainnet as [`USDCDeployment`].
static USDC_XDC: Lazy<USDCDeployment> = Lazy::new(|| {
    USDCDeployment(TokenDeployment {
        asset: TokenAsset {
            address: address!("0x2A8E898b6242355c290E1f4Fc966b8788729A4D4").into(),
            network: Network::XdcMainnet,
        },
        decimals: 6,
        eip712: Some(TokenDeploymentEip712 {
            name: "Bridged USDC(XDC)".into(),
            version: "2".into(),
        }),
    })
});

/// Lazily initialized known USDC deployment on Avalanche Fuji testnet as [`USDCDeployment`].
static USDC_AVALANCHE_FUJI: Lazy<USDCDeployment> = Lazy::new(|| {
    USDCDeployment(TokenDeployment {
        asset: TokenAsset {
            address: address!("0x5425890298aed601595a70AB815c96711a31Bc65").into(),
            network: Network::AvalancheFuji,
        },
        decimals: 6,
        eip712: Some(TokenDeploymentEip712 {
            name: "USD Coin".into(),
            version: "2".into(),
        }),
    })
});

/// Lazily initialized known USDC deployment on Avalanche Fuji testnet as [`USDCDeployment`].
static USDC_AVALANCHE: Lazy<USDCDeployment> = Lazy::new(|| {
    USDCDeployment(TokenDeployment {
        asset: TokenAsset {
            address: address!("0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E").into(),
            network: Network::Avalanche,
        },
        decimals: 6,
        eip712: Some(TokenDeploymentEip712 {
            name: "USD Coin".into(),
            version: "2".into(),
        }),
    })
});

/// Lazily initialized known USDC deployment on Solana mainnet as [`USDCDeployment`].
static USDC_SOLANA: Lazy<USDCDeployment> = Lazy::new(|| {
    USDCDeployment(TokenDeployment {
        asset: TokenAsset {
            address: MixedAddress::Solana(
                Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap(),
            ),
            network: Network::Solana,
        },
        decimals: 6,
        eip712: None,
    })
});

/// Lazily initialized known USDC deployment on Solana mainnet as [`USDCDeployment`].
static USDC_SOLANA_DEVNET: Lazy<USDCDeployment> = Lazy::new(|| {
    USDCDeployment(TokenDeployment {
        asset: TokenAsset {
            address: MixedAddress::Solana(
                Pubkey::from_str("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU").unwrap(),
            ),
            network: Network::SolanaDevnet,
        },
        decimals: 6,
        eip712: None,
    })
});

/// Lazily initialized known USDC deployment on Polygon Amoy testnet as [`USDCDeployment`].
static USDC_POLYGON_AMOY: Lazy<USDCDeployment> = Lazy::new(|| {
    USDCDeployment(TokenDeployment {
        asset: TokenAsset {
            address: address!("0x41E94Eb019C0762f9Bfcf9Fb1E58725BfB0e7582").into(),
            network: Network::PolygonAmoy,
        },
        decimals: 6,
        eip712: Some(TokenDeploymentEip712 {
            name: "USDC".into(),
            version: "2".into(),
        }),
    })
});

/// Lazily initialized known USDC deployment on Polygon mainnet as [`USDCDeployment`].
static USDC_POLYGON: Lazy<USDCDeployment> = Lazy::new(|| {
    USDCDeployment(TokenDeployment {
        asset: TokenAsset {
            address: address!("0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359").into(),
            network: Network::Polygon,
        },
        decimals: 6,
        eip712: Some(TokenDeploymentEip712 {
            name: "USDC".into(),
            version: "2".into(),
        }),
    })
});

static USDC_SEI: Lazy<USDCDeployment> = Lazy::new(|| {
    USDCDeployment(TokenDeployment {
        asset: TokenAsset {
            address: address!("0xe15fC38F6D8c56aF07bbCBe3BAf5708A2Bf42392").into(),
            network: Network::Sei,
        },
        decimals: 6,
        eip712: Some(TokenDeploymentEip712 {
            name: "USDC".into(),
            version: "2".into(),
        }),
    })
});

static USDC_SEI_TESTNET: Lazy<USDCDeployment> = Lazy::new(|| {
    USDCDeployment(TokenDeployment {
        asset: TokenAsset {
            address: address!("0x4fCF1784B31630811181f670Aea7A7bEF803eaED").into(),
            network: Network::Sei,
        },
        decimals: 6,
        eip712: Some(TokenDeploymentEip712 {
            name: "USDC".into(),
            version: "2".into(),
        }),
    })
});

/// Lazily initialized known xBNB deployment on BSC testnet as [`USDCDeployment`].
static XBNB_BSC_TESTNET: Lazy<USDCDeployment> = Lazy::new(|| {
    USDCDeployment(TokenDeployment {
        asset: TokenAsset {
            address: address!("0x1E11fF9f392dAAbFB8823F210624194298FCF3E2").into(),
            network: Network::BscTestnet,
        },
        decimals: 18,
        eip712: Some(TokenDeploymentEip712 {
            name: "x402 BNB".into(),
            version: "1".into(),
        }),
    })
});

/// Lazily initialized known xBNB deployment on BSC mainnet as [`USDCDeployment`].
static XBNB_BSC: Lazy<USDCDeployment> = Lazy::new(|| {
    USDCDeployment(TokenDeployment {
        asset: TokenAsset {
            address: address!("0x1E11fF9f392dAAbFB8823F210624194298FCF3E2").into(),
            network: Network::Bsc,
        },
        decimals: 18,
        eip712: Some(TokenDeploymentEip712 {
            name: "x402 BNB".into(),
            version: "1".into(),
        }),
    })
});

/// Lazily initialized known USDC deployment on XRPL EVM as [`USDCDeployment`].
static USDC_XRPL_EVM: Lazy<USDCDeployment> = Lazy::new(|| {
    USDCDeployment(TokenDeployment {
        asset: TokenAsset {
            // Note: This is a placeholder address - actual deployment TBD
            address: address!("0x0000000000000000000000000000000000000000").into(),
            network: Network::XrplEvm,
        },
        decimals: 6,
        eip712: Some(TokenDeploymentEip712 {
            name: "USD Coin".into(),
            version: "1".into(),
        }),
    })
});

/// Lazily initialized known USDC deployment on Peaq as [`USDCDeployment`].
static USDC_PEAQ: Lazy<USDCDeployment> = Lazy::new(|| {
    USDCDeployment(TokenDeployment {
        asset: TokenAsset {
            // Note: This is a placeholder address - actual deployment TBD
            address: address!("0x0000000000000000000000000000000000000000").into(),
            network: Network::Peaq,
        },
        decimals: 6,
        eip712: Some(TokenDeploymentEip712 {
            name: "USD Coin".into(),
            version: "1".into(),
        }),
    })
});

/// Lazily initialized known USDC deployment on IoTeX as [`USDCDeployment`].
static USDC_IOTEX: Lazy<USDCDeployment> = Lazy::new(|| {
    USDCDeployment(TokenDeployment {
        asset: TokenAsset {
            // IoTeX USDC deployment
            address: address!("0x3B2bf2b523f54C4E454F08Aa286D03115aFF326c").into(),
            network: Network::IoTeX,
        },
        decimals: 6,
        eip712: Some(TokenDeploymentEip712 {
            name: "USD Coin".into(),
            version: "1".into(),
        }),
    })
});

/// Lazily initialized known USDC deployment on Celo mainnet as [`USDCDeployment`].
static USDC_CELO: Lazy<USDCDeployment> = Lazy::new(|| {
    USDCDeployment(TokenDeployment {
        asset: TokenAsset {
            // Native USDC on Celo
            address: address!("0xcebA9300f2b948710d2653dD7B07f33A8B32118C").into(),
            network: Network::Celo,
        },
        decimals: 6,
        eip712: Some(TokenDeploymentEip712 {
            name: "USD Coin".into(),
            version: "2".into(),
        }),
    })
});

/// Lazily initialized known USDC deployment on Celo Alfajores testnet as [`USDCDeployment`].
static USDC_CELO_ALFAJORES: Lazy<USDCDeployment> = Lazy::new(|| {
    USDCDeployment(TokenDeployment {
        asset: TokenAsset {
            // Celo Alfajores testnet USDC
            address: address!("0x2F25deB3848C207fc8E0c34035B3Ba7fC157602B").into(),
            network: Network::CeloAlfajores,
        },
        decimals: 6,
        eip712: Some(TokenDeploymentEip712 {
            name: "USDC".into(),
            version: "2".into(),
        }),
    })
});

/// Placeholder for Aptos USDC (non-EVM, uses different address format).
static USDC_APTOS: Lazy<USDCDeployment> = Lazy::new(|| {
    USDCDeployment(TokenDeployment {
        asset: TokenAsset {
            // Aptos uses Move addresses, this is a placeholder
            address: MixedAddress::Offchain(
                "0xf22bede237a07e121b56d91a491eb7bcdfd1f5907926a9e58338f964a01b17fa::asset::USDC"
                    .to_string(),
            ),
            network: Network::Aptos,
        },
        decimals: 6,
        eip712: None,
    })
});

/// Placeholder for Aptos Testnet USDC.
static USDC_APTOS_TESTNET: Lazy<USDCDeployment> = Lazy::new(|| {
    USDCDeployment(TokenDeployment {
        asset: TokenAsset {
            address: MixedAddress::Offchain(
                "0xf22bede237a07e121b56d91a491eb7bcdfd1f5907926a9e58338f964a01b17fa::asset::USDC"
                    .to_string(),
            ),
            network: Network::AptosTestnet,
        },
        decimals: 6,
        eip712: None,
    })
});

/// A known USDC deployment as a wrapper around [`TokenDeployment`].
#[derive(Clone, Debug)]
pub struct USDCDeployment(pub TokenDeployment);

impl Deref for USDCDeployment {
    type Target = TokenDeployment;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&USDCDeployment> for TokenDeployment {
    fn from(deployment: &USDCDeployment) -> Self {
        deployment.0.clone()
    }
}

impl From<USDCDeployment> for Vec<TokenAsset> {
    fn from(deployment: USDCDeployment) -> Self {
        vec![deployment.asset.clone()]
    }
}

impl From<&USDCDeployment> for Vec<TokenAsset> {
    fn from(deployment: &USDCDeployment) -> Self {
        vec![deployment.asset.clone()]
    }
}

impl USDCDeployment {
    /// Return the known USDC deployment for the given network.
    ///
    /// Panic if the network is unsupported (not expected in practice).
    pub fn by_network<N: Borrow<Network>>(network: N) -> &'static USDCDeployment {
        match network.borrow() {
            Network::BaseSepolia => &USDC_BASE_SEPOLIA,
            Network::Base => &USDC_BASE,
            Network::XdcMainnet => &USDC_XDC,
            Network::AvalancheFuji => &USDC_AVALANCHE_FUJI,
            Network::Avalanche => &USDC_AVALANCHE,
            Network::Solana => &USDC_SOLANA,
            Network::SolanaDevnet => &USDC_SOLANA_DEVNET,
            Network::PolygonAmoy => &USDC_POLYGON_AMOY,
            Network::Polygon => &USDC_POLYGON,
            Network::Sei => &USDC_SEI,
            Network::SeiTestnet => &USDC_SEI_TESTNET,
            Network::BscTestnet => &XBNB_BSC_TESTNET,
            Network::Bsc => &XBNB_BSC,
            Network::XrplEvm => &USDC_XRPL_EVM,
            Network::Peaq => &USDC_PEAQ,
            Network::IoTeX => &USDC_IOTEX,
            Network::Celo => &USDC_CELO,
            Network::CeloAlfajores => &USDC_CELO_ALFAJORES,
            Network::Aptos => &USDC_APTOS,
            Network::AptosTestnet => &USDC_APTOS_TESTNET,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_to_chain_id() {
        assert_eq!(Network::Base.to_chain_id().to_string(), "eip155:8453");
        assert_eq!(
            Network::BaseSepolia.to_chain_id().to_string(),
            "eip155:84532"
        );
        assert_eq!(Network::Solana.to_chain_id().to_string(), "solana:mainnet");
        assert_eq!(Network::Aptos.to_chain_id().to_string(), "aptos:mainnet");
    }

    #[test]
    fn test_chain_id_to_network() {
        let chain_id = ChainId::eip155(8453);
        assert_eq!(Network::try_from(&chain_id).unwrap(), Network::Base);

        let solana = ChainId::solana_mainnet();
        assert_eq!(Network::try_from(&solana).unwrap(), Network::Solana);

        let aptos = ChainId::aptos_mainnet();
        assert_eq!(Network::try_from(&aptos).unwrap(), Network::Aptos);
    }

    #[test]
    fn test_network_roundtrip() {
        for network in Network::variants() {
            let chain_id = network.to_chain_id();
            let recovered = Network::try_from(&chain_id).unwrap();
            assert_eq!(*network, recovered, "roundtrip failed for {network:?}");
        }
    }

    #[test]
    fn test_evm_chain_id() {
        assert_eq!(Network::Base.evm_chain_id(), Some(8453));
        assert_eq!(Network::Celo.evm_chain_id(), Some(42220));
        assert_eq!(Network::Solana.evm_chain_id(), None);
        assert_eq!(Network::Aptos.evm_chain_id(), None);
    }

    #[test]
    fn test_network_family() {
        assert_eq!(Network::Base.family(), NetworkFamily::Evm);
        assert_eq!(Network::Celo.family(), NetworkFamily::Evm);
        assert_eq!(Network::Solana.family(), NetworkFamily::Solana);
        assert_eq!(Network::Aptos.family(), NetworkFamily::Aptos);
    }

    #[test]
    fn test_is_testnet() {
        assert!(Network::BaseSepolia.is_testnet());
        assert!(Network::CeloAlfajores.is_testnet());
        assert!(Network::AptosTestnet.is_testnet());
        assert!(!Network::Base.is_testnet());
        assert!(!Network::Celo.is_testnet());
        assert!(!Network::Aptos.is_testnet());
    }
}
