use dcbor::{CBORCase, CBOR};
use quantum_link_macros::Cbor;

#[derive(Debug, Clone, PartialEq, Cbor)]
pub struct TestStruct {
    #[n(0)]
    pub name: String,
    #[n(1)]
    pub value: u64,
    #[n(2)]
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Cbor)]
pub struct TestWithVec {
    #[n(0)]
    pub items: Vec<u8>,
    #[n(1)]
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Cbor)]
pub struct TestWithArray {
    #[n(0)]
    pub hash: [u8; 32],
    #[n(1)]
    pub id: u64,
}

#[derive(Debug, Clone, PartialEq, Cbor)]
pub enum TestEnumTuple {
    #[n(0)]
    First(TestStruct),
    #[n(1)]
    Second(TestWithVec),
}

#[derive(Debug, Clone, PartialEq, Cbor)]
pub enum TestEnumStruct {
    #[n(0)]
    VariantA {
        #[n(0)]
        count: u64,
        #[n(1)]
        active: bool,
    },
    #[n(1)]
    VariantB {
        #[n(0)]
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Cbor)]
pub enum TestEnumUnit {
    #[n(0)]
    Empty,
    #[n(1)]
    WithData(TestStruct),
}

#[derive(Debug, Clone, PartialEq, Cbor)]
pub enum TestEnumMixed {
    #[n(0)]
    Unit,
    #[n(1)]
    Tuple(TestStruct),
    #[n(2)]
    Struct {
        #[n(0)]
        field1: String,
        #[n(1)]
        field2: u64,
    },
}

#[test]
fn struct_roundtrip() {
    let original = TestStruct {
        name: "test".to_string(),
        value: 42,
        enabled: true,
    };

    let cbor: CBOR = original.clone().into();
    let recovered: TestStruct = cbor.try_into().unwrap();

    assert_eq!(original, recovered);
}

#[test]
fn struct_with_vec_roundtrip() {
    let original = TestWithVec {
        items: vec![1, 2, 3, 4, 5],
        label: "data".to_string(),
    };

    let cbor: CBOR = original.clone().into();
    let recovered: TestWithVec = cbor.try_into().unwrap();

    assert_eq!(original, recovered);
}

#[test]
fn struct_with_array_roundtrip() {
    let original = TestWithArray {
        hash: [
            0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c,
        ],
        id: 12345,
    };

    let cbor: CBOR = original.clone().into();
    let recovered: TestWithArray = cbor.try_into().unwrap();

    assert_eq!(original, recovered);
}

#[test]
fn byte_string_encoding() {
    let test = TestWithVec {
        items: vec![1, 2, 3],
        label: "test".to_string(),
    };

    let cbor: CBOR = test.into();
    let case = cbor.into_case();

    match case {
        CBORCase::Map(map) => {
            let items_cbor: CBOR = map.get(0).unwrap();
            let items_case = items_cbor.into_case();
            assert!(
                matches!(items_case, CBORCase::ByteString(_)),
                "Vec<u8> should be encoded as byte string"
            );
        }
        _ => panic!("Expected CBOR map"),
    }
}

#[test]
fn array_byte_string_encoding() {
    let test = TestWithArray {
        hash: [0u8; 32],
        id: 1,
    };

    let cbor: CBOR = test.into();
    let case = cbor.into_case();

    match case {
        CBORCase::Map(map) => {
            let hash_cbor: CBOR = map.get(0).unwrap();
            let hash_case = hash_cbor.into_case();
            assert!(
                matches!(hash_case, CBORCase::ByteString(_)),
                "[u8; N] should be encoded as byte string"
            );
        }
        _ => panic!("Expected CBOR map"),
    }
}

#[test]
fn enum_tuple_roundtrip() {
    let test_struct = TestStruct {
        name: "inner".to_string(),
        value: 100,
        enabled: false,
    };

    let original = TestEnumTuple::First(test_struct);
    let cbor: CBOR = original.clone().into();
    let recovered: TestEnumTuple = cbor.try_into().unwrap();

    assert_eq!(original, recovered);

    let test_vec = TestWithVec {
        items: vec![255, 128, 0],
        label: "bytes".to_string(),
    };

    let original2 = TestEnumTuple::Second(test_vec);
    let cbor2: CBOR = original2.clone().into();
    let recovered2: TestEnumTuple = cbor2.try_into().unwrap();

    assert_eq!(original2, recovered2);
}

#[test]
fn enum_struct_roundtrip() {
    let original_a = TestEnumStruct::VariantA {
        count: 999,
        active: true,
    };

    let cbor_a: CBOR = original_a.clone().into();
    let recovered_a: TestEnumStruct = cbor_a.try_into().unwrap();

    assert_eq!(original_a, recovered_a);

    let original_b = TestEnumStruct::VariantB {
        message: "hello world".to_string(),
    };

    let cbor_b: CBOR = original_b.clone().into();
    let recovered_b: TestEnumStruct = cbor_b.try_into().unwrap();

    assert_eq!(original_b, recovered_b);
}

#[test]
fn enum_unit_roundtrip() {
    let original_empty = TestEnumUnit::Empty;
    let cbor: CBOR = original_empty.clone().into();
    let recovered: TestEnumUnit = cbor.try_into().unwrap();

    assert_eq!(original_empty, recovered);

    let test_struct = TestStruct {
        name: "with data".to_string(),
        value: 123,
        enabled: true,
    };

    let original_with_data = TestEnumUnit::WithData(test_struct);
    let cbor2: CBOR = original_with_data.clone().into();
    let recovered2: TestEnumUnit = cbor2.try_into().unwrap();

    assert_eq!(original_with_data, recovered2);
}

#[test]
fn enum_mixed_roundtrip() {
    let unit = TestEnumMixed::Unit;
    let cbor: CBOR = unit.clone().into();
    let recovered: TestEnumMixed = cbor.try_into().unwrap();
    assert_eq!(unit, recovered);

    let tuple = TestEnumMixed::Tuple(TestStruct {
        name: "tuple".to_string(),
        value: 50,
        enabled: false,
    });
    let cbor: CBOR = tuple.clone().into();
    let recovered: TestEnumMixed = cbor.try_into().unwrap();
    assert_eq!(tuple, recovered);

    let struct_var = TestEnumMixed::Struct {
        field1: "struct variant".to_string(),
        field2: 9999,
    };
    let cbor: CBOR = struct_var.clone().into();
    let recovered: TestEnumMixed = cbor.try_into().unwrap();
    assert_eq!(struct_var, recovered);
}

#[test]
fn cbor_structure() {
    let test = TestStruct {
        name: "check".to_string(),
        value: 7,
        enabled: true,
    };

    let cbor: CBOR = test.into();
    let case = cbor.into_case();

    match case {
        CBORCase::Map(map) => {
            assert_eq!(map.len(), 3);

            assert!(map.get::<u64, String>(0).is_some());
            assert!(map.get::<u64, u64>(1).is_some());
            assert!(map.get::<u64, bool>(2).is_some());
        }
        _ => panic!("Expected CBOR map"),
    }
}

#[test]
fn enum_cbor_structure() {
    let test_struct = TestStruct {
        name: "test".to_string(),
        value: 1,
        enabled: true,
    };

    let variant = TestEnumTuple::First(test_struct);
    let cbor: CBOR = variant.into();
    let case = cbor.into_case();

    match case {
        CBORCase::Array(arr) => {
            assert_eq!(arr.len(), 2);

            let index: u64 = arr.get(0).unwrap().clone().try_into().unwrap();
            assert_eq!(index, 0);
        }
        _ => panic!("Expected CBOR array for enum"),
    }
}

#[test]
fn enum_tuple_vs_struct_encoding() {
    #[derive(Debug, Clone, PartialEq, Cbor)]
    pub struct InnerData {
        #[n(0)]
        pub count: u64,
        #[n(1)]
        pub active: bool,
    }

    #[derive(Debug, Clone, PartialEq, Cbor)]
    pub enum EnumWithTupleStruct {
        #[n(0)]
        Variant(InnerData),
    }

    #[derive(Debug, Clone, PartialEq, Cbor)]
    pub enum EnumWithStructFields {
        #[n(0)]
        Variant {
            #[n(0)]
            count: u64,
            #[n(1)]
            active: bool,
        },
    }

    let tuple_enum = EnumWithTupleStruct::Variant(InnerData {
        count: 42,
        active: true,
    });

    let struct_enum = EnumWithStructFields::Variant {
        count: 42,
        active: true,
    };

    let tuple_cbor: CBOR = tuple_enum.into();
    let struct_cbor: CBOR = struct_enum.into();

    let tuple_bytes = tuple_cbor.to_cbor_data();
    let struct_bytes = struct_cbor.to_cbor_data();

    assert_eq!(
        tuple_bytes, struct_bytes,
        "Enum with tuple(struct) should serialize the same as enum with struct fields"
    );
}

#[test]
fn option_array() {
    #[derive(Debug, Clone, PartialEq, Cbor)]
    struct OptionArray {
        #[n(0)]
        arr: Option<[u8; 10]>,
        #[n(1)]
        vec: Option<Vec<u8>>,
    }

    let a = [10; 10];
    let b = vec![12; 4];
    let value = OptionArray {
        arr: Some(a),
        vec: Some(b.clone()),
    };
    let cbor: CBOR = value.into();
    let case = cbor.into_case();

    match case {
        CBORCase::Map(map) => {
            assert_eq!(map.len(), 2);
            let arr: CBOR = map.get(0).unwrap();
            match arr.into_case() {
                CBORCase::ByteString(bytes) => {
                    assert_eq!(bytes.data(), &a)
                }
                _ => panic!("expected bytestring"),
            }
            let vec: CBOR = map.get(1).unwrap();
            match vec.into_case() {
                CBORCase::ByteString(bytes) => {
                    assert_eq!(bytes.data(), &b)
                }
                _ => panic!("expected bytestring"),
            }
        }
        _ => panic!("Expected CBOR array for enum"),
    }
}
