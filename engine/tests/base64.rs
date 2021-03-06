// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use engine::vault::{Base64Decodable, Base64Encodable};

#[test]
fn test_base64() {
    let vectors = [
        [[0x14, 0xfb, 0x9c, 0x03, 0xd9, 0x7e].as_ref(), b"FPucA9l-".as_ref()],
		[b"".as_ref(), b"".as_ref()],
		[b"f".as_ref(), b"Zg==".as_ref()], [b"F".as_ref(), b"Rg==".as_ref()],
		[b"fo".as_ref(), b"Zm8=".as_ref()], [b"FO".as_ref(), b"Rk8=".as_ref()],
		[b"foo".as_ref(), b"Zm9v".as_ref()], [b"FOO".as_ref(), b"Rk9P".as_ref()],
		[b"foob".as_ref(), b"Zm9vYg==".as_ref()], [b"FOOB".as_ref(), b"Rk9PQg==".as_ref()],
		[b"fooba".as_ref(), b"Zm9vYmE=".as_ref()], [b"FOOBA".as_ref(), b"Rk9PQkE=".as_ref()],
		[b"foobar".as_ref(), b"Zm9vYmFy".as_ref()], [b"FOOBAR".as_ref(), b"Rk9PQkFS".as_ref()],
		[
			[0xCA, 0xDD, 0x73, 0xBD, 0x92, 0x1E, 0xB8, 0x3F, 0xF2, 0x80, 0x96, 0x63, 0x17, 0x13, 0xB6, 0xC8, 0x54, 0x22, 0xA5, 0xE5, 0x40, 0xA7, 0x32, 0x5A, 0x6E, 0x41, 0x3F, 0xD5, 0x0B, 0x23, 0xDC, 0xE3, 0x22, 0xB3, 0xB7, 0x59, 0x68, 0xD1, 0xDE, 0x44, 0x31, 0xA3, 0xDF, 0x24, 0x1B, 0x08, 0x8E, 0x17, 0x44, 0xD2, 0xEA, 0x6E, 0x21, 0x72, 0xFB, 0x00, 0x2F, 0x94, 0xC9, 0x59, 0x77, 0x98, 0x78, 0xDD, 0xCB, 0x1F, 0xB9, 0x91, 0x32, 0xD6, 0x38, 0x16, 0x7E, 0xB5, 0xC6, 0x45, 0x9E, 0x50, 0xB8, 0x41, 0x4E, 0xD1, 0x9D, 0xE8, 0x9B, 0xAB, 0x87, 0x9E, 0x43, 0x23, 0xA4, 0x0A, 0x7A, 0x57, 0xEE, 0x35, 0x21, 0xA0, 0xCC, 0xA6, 0xC4, 0xEB, 0x61, 0xC6, 0x31, 0x4B, 0x27, 0x9D, 0xBC, 0x9A, 0x1F, 0x20, 0x15, 0xC8, 0xE1, 0x78, 0xD4, 0xE7, 0x89, 0x3C, 0x17, 0x96, 0x5B, 0x11, 0xFD, 0xA4, 0x41, 0x20, 0x4D, 0x26, 0x27, 0xD5, 0xDD, 0x54, 0x3A, 0x9E, 0x12, 0x17, 0x01, 0x3F, 0xC3, 0x6C, 0x69, 0xB9, 0xDC, 0xEF, 0x89, 0x48, 0xD1, 0x05, 0x4F, 0x56, 0x32, 0x83, 0x05, 0x05, 0x0F, 0x84, 0x62, 0xED, 0x30, 0x6B, 0x5C, 0x77, 0x8B, 0x8A, 0x93, 0xD0, 0x7D, 0xF9, 0x16, 0x96, 0x37, 0x15, 0x13, 0xC2, 0x7D, 0x51, 0x19, 0x0D, 0x7F, 0x55, 0x07, 0x85, 0x7E, 0x9D, 0x09, 0xD0, 0xBF, 0x49, 0x74, 0x7E, 0xA8, 0x01, 0xE4, 0x49, 0x7C, 0x4F, 0x39, 0x9A, 0xF9, 0xF8, 0xC0, 0xCA, 0xB4, 0xB8, 0x3B, 0x91, 0x58, 0xA6, 0x79, 0x90, 0xE3, 0x92, 0xD8, 0x4B, 0x68, 0x57, 0x54, 0xC8, 0x66, 0xA7, 0xD6, 0x3F, 0x4F, 0x0F, 0x0E, 0x42, 0xD3, 0x93, 0x2E, 0x94, 0x31, 0x1E, 0x23, 0xE0, 0x7F, 0x49, 0xBD, 0x46, 0x46, 0x54, 0xE2, 0x7C, 0x8D, 0xE2, 0x54, 0x0C, 0x03, 0x78, 0x2C, 0xBA, 0x5E, 0x73, 0x35, 0x4F, 0x0A, 0x11, 0x21, 0x36, 0x74, 0x0B, 0xD8, 0x81, 0x1F, 0x56, 0x12, 0x0A, 0x80, 0xD4, 0x7D, 0x37, 0xC7, 0x69, 0xE1, 0x6D, 0x64, 0x1C, 0xD9, 0xF5, 0xA3, 0x5C, 0x35, 0x6C, 0x7A, 0xC6, 0x63, 0x3F, 0xDD, 0x8B, 0x46, 0x76, 0xC7, 0x57, 0x9D, 0xE7, 0x26, 0x92, 0xFE, 0x88, 0xB3, 0xB0, 0x77, 0xA9, 0xF5, 0x40, 0xE8, 0x2C, 0x9C, 0xFD, 0x51, 0xDF, 0x5D, 0xE0, 0xC8, 0x3F, 0x18, 0x27, 0xBB, 0xA5, 0x4E, 0xD2, 0xBD, 0xC1, 0xB5, 0xD8, 0x92, 0xE0, 0x7F, 0xB2, 0x3C, 0xE1, 0x41, 0x01, 0x71, 0xEE, 0xEC, 0x9B, 0x38, 0x28, 0x41, 0x10, 0xDA, 0x50, 0xDC, 0x4B, 0x4C, 0xAF, 0x00, 0xFF, 0x3A, 0x01, 0x75, 0xA6, 0x1C, 0xFD, 0x76, 0xA7, 0x0E, 0x85, 0xF4, 0x4B, 0x2D, 0x1B, 0x07, 0xEC, 0x9D, 0xE6, 0x4D, 0x46, 0x22, 0x52, 0xCB, 0xD5, 0xA6, 0x4F, 0x6E, 0x5F, 0xBA, 0x81, 0xA8, 0x9F, 0x64, 0x42, 0xB7, 0x09, 0xCA, 0x0F, 0x73, 0x71, 0x46, 0x4C, 0x63, 0xED, 0x60, 0xD3, 0xAA, 0x1F, 0xAC, 0xAC, 0x88, 0x30, 0xD3, 0x81, 0x3F, 0xD9, 0x9A, 0xFC, 0xA8, 0x09, 0x9B, 0x91, 0x91, 0x81, 0x53, 0xED, 0x11, 0x0D, 0xC0, 0xE4, 0x80, 0xF1, 0x8C, 0x34, 0x07, 0xC5, 0xF1, 0x7A, 0x39, 0x75, 0x68, 0xF7, 0x70, 0xD9, 0x93, 0x92, 0x4C, 0x3E, 0xF8, 0xDE, 0x91, 0x30, 0x67, 0xF0, 0xEB, 0xCF, 0x8C, 0xEC, 0xA8, 0x56, 0x98, 0xB5, 0x05, 0xE7, 0x09, 0x38, 0x77, 0xAE, 0x55, 0x46, 0x1C, 0x6B, 0x89, 0xED, 0xE8, 0x49, 0x77, 0xD5, 0x6D, 0x29, 0xB3, 0x57, 0xED, 0x12, 0x56, 0x73, 0x4E, 0x92, 0xF4, 0x64, 0x0E, 0x44, 0x48, 0x45, 0x8C, 0x2A, 0x14, 0x71, 0xBB, 0xE4, 0x8E, 0x54, 0xFC, 0xE5, 0xD6, 0xA9, 0xD2, 0xE0, 0xC3, 0x58, 0x52, 0xDD, 0xF9, 0x20, 0x80, 0x48, 0x0F, 0xE4, 0x43, 0x62, 0x9F, 0xF1].as_ref(),
			b"yt1zvZIeuD_ygJZjFxO2yFQipeVApzJabkE_1Qsj3OMis7dZaNHeRDGj3yQbCI4XRNLqbiFy-wAvlMlZd5h43csfuZEy1jgWfrXGRZ5QuEFO0Z3om6uHnkMjpAp6V-41IaDMpsTrYcYxSyedvJofIBXI4XjU54k8F5ZbEf2kQSBNJifV3VQ6nhIXAT_DbGm53O-JSNEFT1YygwUFD4Ri7TBrXHeLipPQffkWljcVE8J9URkNf1UHhX6dCdC_SXR-qAHkSXxPOZr5-MDKtLg7kVimeZDjkthLaFdUyGan1j9PDw5C05MulDEeI-B_Sb1GRlTifI3iVAwDeCy6XnM1TwoRITZ0C9iBH1YSCoDUfTfHaeFtZBzZ9aNcNWx6xmM_3YtGdsdXnecmkv6Is7B3qfVA6Cyc_VHfXeDIPxgnu6VO0r3BtdiS4H-yPOFBAXHu7Js4KEEQ2lDcS0yvAP86AXWmHP12pw6F9EstGwfsneZNRiJSy9WmT25fuoGon2RCtwnKD3NxRkxj7WDTqh-srIgw04E_2Zr8qAmbkZGBU-0RDcDkgPGMNAfF8Xo5dWj3cNmTkkw--N6RMGfw68-M7KhWmLUF5wk4d65VRhxrie3oSXfVbSmzV-0SVnNOkvRkDkRIRYwqFHG75I5U_OXWqdLgw1hS3fkggEgP5ENin_E=".as_ref()
		]
    ];

    for vec in vectors.iter() {
        assert_eq!(vec[0].base64().as_bytes(), vec[1]);
        assert_eq!(Vec::from_base64(vec[1]).unwrap(), vec[0]);
    }
}

#[test]
fn base64_fail() {
    let vectors = [
        b"Rg".as_ref(),
        b"Rk8".as_ref(),
        b"Rk9PQk+S".as_ref(),
        b"Zm9vY/Fy".as_ref(),
    ];
    for vec in vectors.iter() {
        assert!(Vec::from_base64(vec).is_err());
    }
}
