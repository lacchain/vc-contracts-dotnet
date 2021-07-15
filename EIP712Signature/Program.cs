using Nethereum.ABI;
using Nethereum.ABI.FunctionEncoding.Attributes;
using Nethereum.Hex.HexConvertors.Extensions;
using Nethereum.Hex.HexTypes;
using Nethereum.Signer;
using Nethereum.Web3;
using Nethereum.Web3.Accounts;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace EIP712Signature {

    [FunctionOutput]
    public class VerificationResult {
        [Parameter( "bool" )]
        public virtual bool CredentialExists { get; set; }
        [Parameter( "bool" )]
        public virtual bool IsNotRevoked { get; set; }
        [Parameter( "bool" )]
        public virtual bool IssuerSignature { get; set; }
        [Parameter( "bool" )]
        public virtual bool HasAdditionalSignatures { get; set; }
        [Parameter( "bool" )]
        public virtual bool IsNotExpired { get; set; }
    }

    class Signature {
        public string R { get; set; }
        public string S { get; set; }
        public byte V { get; set; }
    }

    class Proof {
        public string id { get; set; }
        public string type { get; set; }
        public string proofPurpose { get; set; }
        public string verificationMethod { get; set; }
        public string domain { get; set; }
        public string proofValue { get; set; }
    }

    class CredentialSubject {
        public string id { get; set; }
        public string data { get; set; }
    }

    class VerifiableCredential {
        public string id { get; set; }
        public string issuer { get; set; }
        public string issuanceDate { get; set; }
        public string expirationDate { get; set; }
        public CredentialSubject credentialSubject { get; set; }
        public Proof[] proof { get; set; }
    }

    class EthereumAccount {
        public string Address { get; set; }
        public string PrivateKey { get; set; }
    }


    class ClaimsVerifier {

        private readonly string address;
        private readonly string provider;

        private static readonly HexBigInteger GAS = new HexBigInteger( 4600000 );
        private static readonly string ABI = "[\n    {\n      \"inputs\": [\n        {\n          \"internalType\": \"address\",\n          \"name\": \"_registryAddress\",\n          \"type\": \"address\"\n        }\n      ],\n      \"stateMutability\": \"nonpayable\",\n      \"type\": \"constructor\"\n    },\n    {\n      \"anonymous\": false,\n      \"inputs\": [\n        {\n          \"indexed\": true,\n          \"internalType\": \"bytes32\",\n          \"name\": \"role\",\n          \"type\": \"bytes32\"\n        },\n        {\n          \"indexed\": true,\n          \"internalType\": \"address\",\n          \"name\": \"account\",\n          \"type\": \"address\"\n        },\n        {\n          \"indexed\": true,\n          \"internalType\": \"address\",\n          \"name\": \"sender\",\n          \"type\": \"address\"\n        }\n      ],\n      \"name\": \"RoleGranted\",\n      \"type\": \"event\"\n    },\n    {\n      \"anonymous\": false,\n      \"inputs\": [\n        {\n          \"indexed\": true,\n          \"internalType\": \"bytes32\",\n          \"name\": \"role\",\n          \"type\": \"bytes32\"\n        },\n        {\n          \"indexed\": true,\n          \"internalType\": \"address\",\n          \"name\": \"account\",\n          \"type\": \"address\"\n        },\n        {\n          \"indexed\": true,\n          \"internalType\": \"address\",\n          \"name\": \"sender\",\n          \"type\": \"address\"\n        }\n      ],\n      \"name\": \"RoleRevoked\",\n      \"type\": \"event\"\n    },\n    {\n      \"inputs\": [],\n      \"name\": \"DEFAULT_ADMIN_ROLE\",\n      \"outputs\": [\n        {\n          \"internalType\": \"bytes32\",\n          \"name\": \"\",\n          \"type\": \"bytes32\"\n        }\n      ],\n      \"stateMutability\": \"view\",\n      \"type\": \"function\"\n    },\n    {\n      \"inputs\": [],\n      \"name\": \"ISSUER_ROLE\",\n      \"outputs\": [\n        {\n          \"internalType\": \"bytes32\",\n          \"name\": \"\",\n          \"type\": \"bytes32\"\n        }\n      ],\n      \"stateMutability\": \"view\",\n      \"type\": \"function\"\n    },\n    {\n      \"inputs\": [],\n      \"name\": \"SIGNER_ROLE\",\n      \"outputs\": [\n        {\n          \"internalType\": \"bytes32\",\n          \"name\": \"\",\n          \"type\": \"bytes32\"\n        }\n      ],\n      \"stateMutability\": \"view\",\n      \"type\": \"function\"\n    },\n    {\n      \"inputs\": [\n        {\n          \"internalType\": \"bytes32\",\n          \"name\": \"role\",\n          \"type\": \"bytes32\"\n        }\n      ],\n      \"name\": \"getRoleAdmin\",\n      \"outputs\": [\n        {\n          \"internalType\": \"bytes32\",\n          \"name\": \"\",\n          \"type\": \"bytes32\"\n        }\n      ],\n      \"stateMutability\": \"view\",\n      \"type\": \"function\"\n    },\n    {\n      \"inputs\": [\n        {\n          \"internalType\": \"bytes32\",\n          \"name\": \"role\",\n          \"type\": \"bytes32\"\n        },\n        {\n          \"internalType\": \"uint256\",\n          \"name\": \"index\",\n          \"type\": \"uint256\"\n        }\n      ],\n      \"name\": \"getRoleMember\",\n      \"outputs\": [\n        {\n          \"internalType\": \"address\",\n          \"name\": \"\",\n          \"type\": \"address\"\n        }\n      ],\n      \"stateMutability\": \"view\",\n      \"type\": \"function\"\n    },\n    {\n      \"inputs\": [\n        {\n          \"internalType\": \"bytes32\",\n          \"name\": \"role\",\n          \"type\": \"bytes32\"\n        }\n      ],\n      \"name\": \"getRoleMemberCount\",\n      \"outputs\": [\n        {\n          \"internalType\": \"uint256\",\n          \"name\": \"\",\n          \"type\": \"uint256\"\n        }\n      ],\n      \"stateMutability\": \"view\",\n      \"type\": \"function\"\n    },\n    {\n      \"inputs\": [\n        {\n          \"internalType\": \"bytes32\",\n          \"name\": \"role\",\n          \"type\": \"bytes32\"\n        },\n        {\n          \"internalType\": \"address\",\n          \"name\": \"account\",\n          \"type\": \"address\"\n        }\n      ],\n      \"name\": \"grantRole\",\n      \"outputs\": [],\n      \"stateMutability\": \"nonpayable\",\n      \"type\": \"function\"\n    },\n    {\n      \"inputs\": [\n        {\n          \"internalType\": \"bytes32\",\n          \"name\": \"role\",\n          \"type\": \"bytes32\"\n        },\n        {\n          \"internalType\": \"address\",\n          \"name\": \"account\",\n          \"type\": \"address\"\n        }\n      ],\n      \"name\": \"hasRole\",\n      \"outputs\": [\n        {\n          \"internalType\": \"bool\",\n          \"name\": \"\",\n          \"type\": \"bool\"\n        }\n      ],\n      \"stateMutability\": \"view\",\n      \"type\": \"function\"\n    },\n    {\n      \"inputs\": [\n        {\n          \"internalType\": \"bytes32\",\n          \"name\": \"role\",\n          \"type\": \"bytes32\"\n        },\n        {\n          \"internalType\": \"address\",\n          \"name\": \"account\",\n          \"type\": \"address\"\n        }\n      ],\n      \"name\": \"renounceRole\",\n      \"outputs\": [],\n      \"stateMutability\": \"nonpayable\",\n      \"type\": \"function\"\n    },\n    {\n      \"inputs\": [\n        {\n          \"internalType\": \"bytes32\",\n          \"name\": \"role\",\n          \"type\": \"bytes32\"\n        },\n        {\n          \"internalType\": \"address\",\n          \"name\": \"account\",\n          \"type\": \"address\"\n        }\n      ],\n      \"name\": \"revokeRole\",\n      \"outputs\": [],\n      \"stateMutability\": \"nonpayable\",\n      \"type\": \"function\"\n    },\n    {\n      \"inputs\": [\n        {\n          \"components\": [\n            {\n              \"internalType\": \"address\",\n              \"name\": \"issuer\",\n              \"type\": \"address\"\n            },\n            {\n              \"internalType\": \"address\",\n              \"name\": \"subject\",\n              \"type\": \"address\"\n            },\n            {\n              \"internalType\": \"bytes32\",\n              \"name\": \"data\",\n              \"type\": \"bytes32\"\n            },\n            {\n              \"internalType\": \"uint256\",\n              \"name\": \"validFrom\",\n              \"type\": \"uint256\"\n            },\n            {\n              \"internalType\": \"uint256\",\n              \"name\": \"validTo\",\n              \"type\": \"uint256\"\n            }\n          ],\n          \"internalType\": \"struct ClaimTypes.VerifiableCredential\",\n          \"name\": \"vc\",\n          \"type\": \"tuple\"\n        },\n        {\n          \"internalType\": \"uint8\",\n          \"name\": \"v\",\n          \"type\": \"uint8\"\n        },\n        {\n          \"internalType\": \"bytes32\",\n          \"name\": \"r\",\n          \"type\": \"bytes32\"\n        },\n        {\n          \"internalType\": \"bytes32\",\n          \"name\": \"s\",\n          \"type\": \"bytes32\"\n        }\n      ],\n      \"name\": \"verifyCredential\",\n      \"outputs\": [\n        {\n          \"internalType\": \"bool\",\n          \"name\": \"\",\n          \"type\": \"bool\"\n        },\n        {\n          \"internalType\": \"bool\",\n          \"name\": \"\",\n          \"type\": \"bool\"\n        },\n        {\n          \"internalType\": \"bool\",\n          \"name\": \"\",\n          \"type\": \"bool\"\n        },\n        {\n          \"internalType\": \"bool\",\n          \"name\": \"\",\n          \"type\": \"bool\"\n        },\n        {\n          \"internalType\": \"bool\",\n          \"name\": \"\",\n          \"type\": \"bool\"\n        }\n      ],\n      \"stateMutability\": \"view\",\n      \"type\": \"function\"\n    },\n    {\n      \"inputs\": [\n        {\n          \"components\": [\n            {\n              \"internalType\": \"address\",\n              \"name\": \"issuer\",\n              \"type\": \"address\"\n            },\n            {\n              \"internalType\": \"address\",\n              \"name\": \"subject\",\n              \"type\": \"address\"\n            },\n            {\n              \"internalType\": \"bytes32\",\n              \"name\": \"data\",\n              \"type\": \"bytes32\"\n            },\n            {\n              \"internalType\": \"uint256\",\n              \"name\": \"validFrom\",\n              \"type\": \"uint256\"\n            },\n            {\n              \"internalType\": \"uint256\",\n              \"name\": \"validTo\",\n              \"type\": \"uint256\"\n            }\n          ],\n          \"internalType\": \"struct ClaimTypes.VerifiableCredential\",\n          \"name\": \"vc\",\n          \"type\": \"tuple\"\n        },\n        {\n          \"internalType\": \"bytes\",\n          \"name\": \"_signature\",\n          \"type\": \"bytes\"\n        }\n      ],\n      \"name\": \"verifySigner\",\n      \"outputs\": [\n        {\n          \"internalType\": \"bool\",\n          \"name\": \"\",\n          \"type\": \"bool\"\n        }\n      ],\n      \"stateMutability\": \"view\",\n      \"type\": \"function\"\n    },\n    {\n      \"inputs\": [\n        {\n          \"internalType\": \"address\",\n          \"name\": \"_subject\",\n          \"type\": \"address\"\n        },\n        {\n          \"internalType\": \"bytes32\",\n          \"name\": \"_credentialHash\",\n          \"type\": \"bytes32\"\n        },\n        {\n          \"internalType\": \"uint256\",\n          \"name\": \"_from\",\n          \"type\": \"uint256\"\n        },\n        {\n          \"internalType\": \"uint256\",\n          \"name\": \"_exp\",\n          \"type\": \"uint256\"\n        },\n        {\n          \"internalType\": \"bytes\",\n          \"name\": \"_signature\",\n          \"type\": \"bytes\"\n        }\n      ],\n      \"name\": \"registerCredential\",\n      \"outputs\": [\n        {\n          \"internalType\": \"bool\",\n          \"name\": \"\",\n          \"type\": \"bool\"\n        }\n      ],\n      \"stateMutability\": \"nonpayable\",\n      \"type\": \"function\"\n    },\n    {\n      \"inputs\": [\n        {\n          \"internalType\": \"bytes32\",\n          \"name\": \"_credentialHash\",\n          \"type\": \"bytes32\"\n        },\n        {\n          \"internalType\": \"address\",\n          \"name\": \"issuer\",\n          \"type\": \"address\"\n        },\n        {\n          \"internalType\": \"bytes\",\n          \"name\": \"_signature\",\n          \"type\": \"bytes\"\n        }\n      ],\n      \"name\": \"registerSignature\",\n      \"outputs\": [\n        {\n          \"internalType\": \"bool\",\n          \"name\": \"\",\n          \"type\": \"bool\"\n        }\n      ],\n      \"stateMutability\": \"nonpayable\",\n      \"type\": \"function\"\n    }\n  ]";

        public ClaimsVerifier( string provider, string address ) {
            this.provider = provider;
            this.address = address;
        }

        public string RegisterCredential( EthereumAccount subject, byte[] credentialHash, long issuanceDate, long expirationDate, byte[] signature, EthereumAccount issuer ) {
            var web3 = new Web3( new Account( issuer.PrivateKey ), this.provider );
            var contract = web3.Eth.GetContract( ABI, this.address );

            var registerCredential = contract.GetFunction( "registerCredential" );
            var txHash = registerCredential.SendTransactionAsync( issuer.Address, GAS, new HexBigInteger( 0 ), new HexBigInteger( 0 ),
                                new object[] { subject.Address, credentialHash, issuanceDate, expirationDate, signature } )
                            .ConfigureAwait( false )
                            .GetAwaiter()
                            .GetResult();
            return txHash;
        }

        public string RegisterSignature( byte[] credentialHash, string issuer, byte[] signature, EthereumAccount signer ) {
            var web3 = new Web3( new Account( signer.PrivateKey ), this.provider );
            var contract = web3.Eth.GetContract( ABI, this.address );

            var registerCredential = contract.GetFunction( "registerSignature" );
            var txHash = registerCredential.SendTransactionAsync( signer.Address, GAS, new HexBigInteger( 0 ), new HexBigInteger( 0 ),
                                new object[] { credentialHash, issuer, signature } )
                            .ConfigureAwait( false )
                            .GetAwaiter()
                            .GetResult();
            return txHash;
        }

        public VerificationResult VerifyCredential( string issuer, string subject, byte[] credentialHashHex, double validFrom, double validTo, Signature signature ) {
            var web3 = new Web3( this.provider );
            var contract = web3.Eth.GetContract( ABI, this.address );
            var verifyCredential = contract.GetFunction( "verifyCredential" );
            var verification = verifyCredential.CallDeserializingToObjectAsync<VerificationResult>( new object[] { issuer, subject, credentialHashHex, validFrom, validTo }, signature.V, signature.R.HexToByteArray(), signature.S.HexToByteArray() );

            return verification.Result;
        }

        public bool VerifySigner( string issuer, string subject, byte[] credentialHashHex, double validFrom, double validTo, byte[] signature ) {
            var web3 = new Web3( this.provider );
            var contract = web3.Eth.GetContract( ABI, this.address );
            var verifyCredential = contract.GetFunction( "verifySigner" );
            var verification = verifyCredential.CallAsync<bool>( new object[] { issuer, subject, credentialHashHex, validFrom, validTo }, signature );

            return verification.Result;
        }
    }

    class Program {
        static void Main( string[] args ) {
            var rpcUrl = "https://writer.lacchain.net";
            // var credentialRegistryAddress = "0xA9dF4b312418895c8eba13b749C6C5d1120D290F";
            var claimsVerifierContractAddress = "0xe922b122350040A99097d836E1e16cB16124D302";

            var issuer = new EthereumAccount {
                Address = "0x47adc0faa4f6eb42b499187317949ed99e77ee85",
                PrivateKey = "effa7c6816819ee330bc91f1623f3c66a9fed268ecd5b805a002452075b26c0b"
            };

            var subject = new EthereumAccount {
                Address = "0x4ef9e4721bbf02b84d0e73822ee4e26e95076b9d"
            };

            var signers = new EthereumAccount[] {
                new EthereumAccount {
                    Address = "0x4a5a6460d00c4d8c2835a3067f53fb42021d5bb9",
                    PrivateKey = "09288ce70513941f8a859361aeb243c56d5b7a653c1c68374a70385612fe0c2a"
                },
                new EthereumAccount {
                    Address = "0x4222ec932c5a68b80e71f4ddebb069fa02518b8a",
                    PrivateKey = "6ccfcaa51011057276ef4f574a3186c1411d256e4d7731bdf8743f34e608d1d1"
                }
            };

            SHA256 sha256 = SHA256.Create();
            Encoding enc = Encoding.UTF8;

            VerifiableCredential vc = new VerifiableCredential {
                id = "73bde252-cb3e-44ab-94f9-eba6a8a2f28d",
                issuer = $"did:lac:main:{issuer.Address}",
                issuanceDate = DateTime.UtcNow.ToString( "yyyy-MM-ddTHH:mm:ssZ" ),
                expirationDate = DateTime.UtcNow.AddYears( 1 ).ToString( "yyyy-MM-ddTHH:mm:ssZ" ),
                credentialSubject = new CredentialSubject {
                    id = $"did:lac:main:{subject.Address.ToUpper().Replace( "X", "x" )}",
                    data = "test"
                }
            };

            var credentialSubject = JsonSerializer.Serialize<CredentialSubject>( vc.credentialSubject );
            var credentialHashHex = sha256.ComputeHash( enc.GetBytes( credentialSubject ) );
            var validFrom = new DateTimeOffset( DateTime.Parse( vc.issuanceDate ) ).ToUnixTimeSeconds();
            var validTo = new DateTimeOffset( DateTime.Parse( vc.expirationDate ) ).ToUnixTimeSeconds();

            var VERIFIABLE_CREDENTIAL_TYPEHASH = Web3.Sha3( "VerifiableCredential(address issuer,address subject,bytes32 data,uint256 validFrom,uint256 validTo)" );
            var EIP712DOMAIN_TYPEHASH = Web3.Sha3( "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)" );

            var abiEncode = new ABIEncode();

            var hashEIP712Domain = abiEncode.GetSha3ABIEncoded( new ABIValue( "bytes32", strToToHexByte( EIP712DOMAIN_TYPEHASH ) ), new ABIValue( "bytes32", strToToHexByte( Web3.Sha3( "EIP712Domain" ) ) ), new ABIValue( "bytes32", strToToHexByte( Web3.Sha3( "1" ) ) ), new ABIValue( "uint256", 648529 ), new ABIValue( "address", claimsVerifierContractAddress ) );
            var encodeHashCredential = abiEncode.GetSha3ABIEncoded( new ABIValue( "bytes32", strToToHexByte( VERIFIABLE_CREDENTIAL_TYPEHASH ) ), new ABIValue( "address", issuer.Address ), new ABIValue( "address", subject.Address ), new ABIValue( "bytes32", credentialHashHex ), new ABIValue( "uint256", validFrom ), new ABIValue( "uint256", validTo ) );
            var credentialHash = abiEncode.GetSha3ABIEncodedPacked( new ABIValue( "bytes", strToToHexByte( "0x1901" ) ), new ABIValue( "bytes32", hashEIP712Domain ), new ABIValue( "bytes32", encodeHashCredential ) ).ToHex();

            var signature = ParseSignature( new EthECKey( issuer.PrivateKey ).SignAndCalculateV( strToToHexByte( credentialHash ) ) );

            ClaimsVerifier claimsVerifier = new ClaimsVerifier( rpcUrl, claimsVerifierContractAddress );

            // REGISTER CREDENTIAL
            var tx = claimsVerifier.RegisterCredential( subject, strToToHexByte( credentialHash ), validFrom, validTo, signature, issuer );

            Console.Out.WriteLine( "Tx: " + tx );

            Thread.Sleep( 2000 );

            // VERIFY CREDENTIAL
            Signature issuerSignature = GetSignature( signature.ToHex() );
            VerificationResult verification = claimsVerifier.VerifyCredential( issuer.Address, subject.Address, credentialHashHex, validFrom, validTo, issuerSignature );

            Console.Out.WriteLine( "Credential Exists: " + verification.CredentialExists );
            Console.Out.WriteLine( "Is Not Revoked: " + verification.IsNotRevoked );
            Console.Out.WriteLine( "Issuer Signature: " + verification.IssuerSignature );
            Console.Out.WriteLine( "Additional Signatures: " + verification.HasAdditionalSignatures );
            Console.Out.WriteLine( "Is Not Expired: " + verification.IsNotExpired );

            // ADD SIGNATURE FOR SIGNER 1
            var signatureSigner1 = ParseSignature( new EthECKey( signers[0].PrivateKey ).SignAndCalculateV( credentialHash.HexToByteArray() ) );
            claimsVerifier.RegisterSignature( credentialHash.HexToByteArray(), issuer.Address, signatureSigner1, signers[0] );


            // ADD SIGNATURE FOR SIGNER 2
            var signatureSigner2 = ParseSignature( new EthECKey( signers[1].PrivateKey ).SignAndCalculateV( credentialHash.HexToByteArray() ) );
            claimsVerifier.RegisterSignature( credentialHash.HexToByteArray(), issuer.Address, signatureSigner2, signers[1] );

            Thread.Sleep( 10000 );

            // VERIFY CREDENTIAL AGAIN
            VerificationResult verification2 = claimsVerifier.VerifyCredential( issuer.Address, subject.Address, credentialHashHex, validFrom, validTo, issuerSignature );
            Console.Out.WriteLine( "Now have additional signatures: " + verification2.HasAdditionalSignatures );

            // VERIFY SIGNATURE OF SIGNER 1
            bool verifySigner1 = claimsVerifier.VerifySigner( issuer.Address, subject.Address, credentialHashHex, validFrom, validTo, signatureSigner1 );
            Console.Out.WriteLine( "Valid Signature 1: " + verifySigner1 );

            // VERIFY SIGNATURE OF SIGNER 2
            bool verifySigner2 = claimsVerifier.VerifySigner( issuer.Address, subject.Address, credentialHashHex, validFrom, validTo, signatureSigner2 );
            Console.Out.WriteLine( "Valid Signature 2: " + verifySigner2 );
        }

        private static byte[] ParseSignature( EthECDSASignature signature ) {
            var fullSignature = signature.To64ByteArray().ToHex() + signature.V.ToHex();
            return fullSignature.HexToByteArray();
        }

        private static byte[] strToToHexByte( string hexString ) {
            hexString = hexString.Replace( " ", "" );
            hexString = hexString.Replace( "0x", "" );
            if( ( hexString.Length % 2 ) != 0 )
                hexString += " ";
            byte[] returnBytes = new byte[hexString.Length / 2];
            for( int i = 0; i < returnBytes.Length; i++ )
                returnBytes[i] = Convert.ToByte( hexString.Substring( i * 2, 2 ), 16 );
            return returnBytes;
        }

        private static Signature GetSignature( string fullSig ) {
            if( fullSig.StartsWith( "0x" ) )
                fullSig = fullSig[2..];
            return new Signature {
                R = "0x" + fullSig.Substring( 0, 64 ),
                S = "0x" + fullSig.Substring( 64, 64 ),
                V = Convert.ToByte( fullSig.Substring( 128, 2 ), 16 )
            };
        }
    }
}
